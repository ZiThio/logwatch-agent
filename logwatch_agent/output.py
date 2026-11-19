"""Alert output: immediate alert records and background AI explanations.

Every line of the alerts file is a JSON object with a ``record_type``:

* ``"alert"`` is written as soon as a rule fires. With AI enabled its
  ``analysis`` is ``{"status": "pending"}``; without AI it is ``null``.
* ``"analysis"`` is written later by the background worker, linked to its
  alert by ``alert_id``. It holds the explanation or an ``error``.

Detection never waits for the AI: a slow model only delays the analysis line.
"""

from __future__ import annotations

import json
import queue
import sys
import threading
from pathlib import Path
from typing import Callable, Protocol

from .core import Alert

DEFAULT_MAX_PENDING = 100


class Explainer(Protocol):
    def explain(self, alert: Alert) -> dict[str, object]: ...


class AlertWriter:
    """Appends JSON records to the alerts file and echoes them; thread-safe."""

    def __init__(self, output: Path, emit: Callable[[str], None] = print) -> None:
        self.output = output
        self.emit = emit
        self._lock = threading.Lock()

    def write(self, record: dict[str, object]) -> None:
        payload = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self.output.parent.mkdir(parents=True, exist_ok=True)
            with self.output.open("a", encoding="utf-8") as stream:
                stream.write(payload + "\n")
            self.emit(payload)


def alert_record(alert: Alert) -> dict[str, object]:
    return {"record_type": "alert", **alert.to_dict()}


def analysis_record(alert: Alert, analysis: dict[str, object]) -> dict[str, object]:
    return {
        "record_type": "analysis",
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "analysis": analysis,
    }


def explain_safely(explainer: Explainer, alert: Alert) -> dict[str, object]:
    """Never raises: an AI failure becomes an ``error`` analysis."""
    try:
        return explainer.explain(alert)
    except Exception as exc:  # noqa: BLE001 - the worker thread must survive any failure
        message = f"AI explanation unavailable: {exc}"
        print(f"Warning: {message}", file=sys.stderr)
        return {"error": message}


class ExplanationWorker:
    """Explains alerts one at a time on a background thread.

    ``submit`` returns immediately. The queue is bounded so that an alert storm
    cannot pile up unbounded work for a slow model.
    """

    def __init__(
        self,
        explainer: Explainer,
        writer: AlertWriter,
        *,
        max_pending: int = DEFAULT_MAX_PENDING,
    ) -> None:
        self._explainer = explainer
        self._writer = writer
        self._queue: queue.Queue[Alert] = queue.Queue(maxsize=max_pending)
        self._thread = threading.Thread(target=self._run, name="ai-explainer", daemon=True)
        self._thread.start()

    def submit(self, alert: Alert) -> bool:
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            return False
        return True

    def pending(self) -> int:
        """Alerts queued or being explained right now."""
        return self._queue.unfinished_tasks

    def wait(self) -> None:
        """Block until every submitted alert has its analysis record."""
        self._queue.join()

    def _run(self) -> None:
        while True:
            alert = self._queue.get()
            try:
                analysis = explain_safely(self._explainer, alert)
                self._writer.write(analysis_record(alert, analysis))
            except Exception as exc:  # noqa: BLE001 - e.g. disk full; keep serving
                print(f"Warning: could not write analysis: {exc}", file=sys.stderr)
            finally:
                self._queue.task_done()


def handle_alert(
    alert: Alert, *, writer: AlertWriter, worker: ExplanationWorker | None
) -> None:
    """Write the alert now; hand it to the worker for an explanation if AI is on."""
    if worker is not None:
        alert.analysis = {"status": "pending"}
    writer.write(alert_record(alert))
    if worker is not None and not worker.submit(alert):
        writer.write(
            analysis_record(
                alert,
                {"error": "AI explanation skipped: too many alerts are waiting for one"},
            )
        )
