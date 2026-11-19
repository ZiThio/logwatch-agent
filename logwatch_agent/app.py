from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .core import RuleDetector, parse_log_line
from .follower import FileFollower
from .ollama import DEFAULT_TIMEOUT_SECONDS, OllamaClient
from .output import AlertWriter, ExplanationWorker, handle_alert

# qwen3:8b gave the most accurate explanations in testing. On CPU-only machines
# it can take about a minute per alert; --model qwen2.5:3b is faster but less
# reliable (it misread the firewall policy in the demo).
DEFAULT_CHAT_MODEL = "qwen3:8b"
from .rag import DEFAULT_MAX_DISTANCE, AlertExplainer, ChromaKnowledgeBase
from .state import StateStore


def _positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number of seconds") from exc
    if seconds <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return seconds


def _add_ollama_timeout(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ollama-timeout",
        type=_positive_seconds,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Seconds to wait for each Ollama request (default: {DEFAULT_TIMEOUT_SECONDS:g})",
    )


def _add_ai_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ai", action="store_true", help="Explain alerts with local Ollama + RAG")
    parser.add_argument("--model", default=DEFAULT_CHAT_MODEL, help="Ollama chat model")
    parser.add_argument(
        "--embedding-model", default="nomic-embed-text", help="Ollama embedding model"
    )
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    _add_ollama_timeout(parser)
    parser.add_argument("--chroma-dir", type=Path, default=Path(".state/chroma"))
    parser.add_argument("--runbooks", type=Path, default=Path("runbooks"))
    parser.add_argument(
        "--runbook-max-distance",
        type=_distance,
        default=DEFAULT_MAX_DISTANCE,
        help=(
            "Ignore runbook passages less similar than this cosine distance "
            f"(0 = identical, lower is stricter; default: {DEFAULT_MAX_DISTANCE:g})"
        ),
    )


def _distance(value: str) -> float:
    try:
        distance = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not 0 < distance <= 2:
        raise argparse.ArgumentTypeError("must be greater than 0 and at most 2")
    return distance


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logwatch-agent",
        description="Monitor local logs, detect event bursts, and optionally explain alerts with RAG.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    replay = subparsers.add_parser("replay", help="Read a log file once from beginning to end")
    replay.add_argument("--log", type=Path, required=True)
    replay.add_argument("--alerts", type=Path, default=Path("alerts.jsonl"))
    _add_ai_options(replay)

    watch = subparsers.add_parser("watch", help="Continuously monitor an appended log file")
    watch.add_argument("--log", type=Path, required=True)
    watch.add_argument("--alerts", type=Path, default=Path("alerts.jsonl"))
    watch.add_argument("--state-dir", type=Path, default=Path(".state"))
    watch.add_argument("--interval", type=float, default=1.0)
    _add_ai_options(watch)

    index = subparsers.add_parser("index", help="Index Markdown/text runbooks in ChromaDB")
    index.add_argument("--runbooks", type=Path, default=Path("runbooks"))
    index.add_argument("--chroma-dir", type=Path, default=Path(".state/chroma"))
    index.add_argument("--embedding-model", default="nomic-embed-text")
    index.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    _add_ollama_timeout(index)
    index.add_argument("--rebuild", action="store_true", help="Replace the existing runbook index")
    return parser


def _make_explainer(args: argparse.Namespace) -> AlertExplainer | None:
    if not getattr(args, "ai", False):
        return None
    client = OllamaClient(args.ollama_url, timeout=args.ollama_timeout)
    knowledge_base = ChromaKnowledgeBase(
        args.chroma_dir,
        client,
        args.embedding_model,
        max_distance=args.runbook_max_distance,
    )
    knowledge_base.index_directory(args.runbooks)
    return AlertExplainer(knowledge_base, client, args.model)


def _make_worker(args: argparse.Namespace, writer: AlertWriter) -> ExplanationWorker | None:
    explainer = _make_explainer(args)
    return ExplanationWorker(explainer, writer) if explainer is not None else None


def _process_lines(
    lines: list[str],
    detector: RuleDetector,
    *,
    writer: AlertWriter,
    worker: ExplanationWorker | None,
    state: StateStore | None = None,
) -> int:
    emitted = 0
    for line in lines:
        event = parse_log_line(line)
        if event is None:
            continue
        for alert in detector.observe(event):
            if state is not None and state.has_alert(alert.alert_id):
                continue
            handle_alert(alert, writer=writer, worker=worker)
            if state is not None:
                state.save_alert_once(alert)
            emitted += 1
    return emitted


def _run_replay(args: argparse.Namespace) -> int:
    writer = AlertWriter(args.alerts)
    worker = _make_worker(args, writer)
    detector = RuleDetector()
    with args.log.open("r", encoding="utf-8", errors="replace") as stream:
        count = _process_lines(stream.readlines(), detector, writer=writer, worker=worker)
    if worker is not None and worker.pending():
        print(f"Waiting for {worker.pending()} AI explanation(s)...")
        worker.wait()
    print(f"Replay complete: {count} alert(s).")
    return 0


def _run_watch(args: argparse.Namespace) -> int:
    if args.interval <= 0:
        raise ValueError("--interval must be greater than zero")
    writer = AlertWriter(args.alerts)
    worker = _make_worker(args, writer)
    args.state_dir.mkdir(parents=True, exist_ok=True)
    state = StateStore(args.state_dir / "monitor.sqlite3")
    follower = FileFollower(args.log, state)
    detector = RuleDetector()
    print(f"Watching {args.log} (Ctrl+C to stop).")
    if not args.log.exists():
        # Normal before a collector writes its first line (e.g. the lab is still
        # starting). The follower keeps polling until the file appears.
        print(f"Waiting for {args.log} to be created.")
    try:
        while True:
            _process_lines(
                follower.read_new_lines(),
                detector,
                writer=writer,
                worker=worker,
                state=state,
            )
            follower.commit()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        if worker is not None and worker.pending():
            # The alerts themselves are already saved; only their analyses are lost.
            print(f"{worker.pending()} AI explanation(s) were not finished.")
    finally:
        state.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "index":
            client = OllamaClient(args.ollama_url, timeout=args.ollama_timeout)
            knowledge_base = ChromaKnowledgeBase(
                args.chroma_dir, client, args.embedding_model
            )
            count = knowledge_base.index_directory(args.runbooks, rebuild=args.rebuild)
            print(f"Indexed {count} runbook chunk(s) in {args.chroma_dir}.")
            return 0
        if args.command == "replay":
            if not args.log.is_file():
                raise FileNotFoundError(f"Log file not found: {args.log}")
            return _run_replay(args)
        # watch: a missing file is fine (it is waited for); a directory is not.
        if args.log.exists() and not args.log.is_file():
            raise ValueError(f"Not a regular file: {args.log}")
        return _run_watch(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
