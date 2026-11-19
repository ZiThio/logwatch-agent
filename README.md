# LogWatch Agent

Local-first continuous monitoring for system and firewall logs. The first
version is intentionally small: it tails a local file, detects a few
explainable event bursts, and can optionally use local Ollama models plus
ChromaDB to explain an alert using imported runbooks.

## The problem and the added value

**Problem:** Administrators may need to sift through large volumes of raw,
disconnected log lines to notice a developing incident and find the relevant
troubleshooting procedure.

**Added value:** LogWatch turns a small set of explicit detection rules into
deduplicated alerts with the exact supporting log lines. When enabled, local
RAG adds relevant runbook passages and an AI-generated explanation, keeping the
evidence and the explanation visible together.

**Valeur ajoutée :** transformer des journaux bruts en alertes compréhensibles,
vérifiables et reliées à une documentation pertinente.

## Architecture

```text
Appended log file
       |
       v
File follower -- SQLite cursor (resume after restart)
       |
       v
Parser and rule detector -- burst thresholds / cooldown
       |
       v
Alert JSONL + console (rule and exact log evidence)
       |
       +-- optional: Ollama embedding -> ChromaDB runbook retrieval
                             |
                             v
                     local Ollama chat model
                             |
                             v
              explanation, checks, runbook references
```

Detection is deterministic and does not call an LLM for every log line. The
optional chat model only explains an alert. It cannot connect to network
equipment, run commands, or change configuration. Log lines and runbook content
are treated as untrusted evidence.

## Requirements

- Python 3.10+
- No third-party packages for replay, file following, and rule-based detection
- Optional RAG: Ollama, ChromaDB, and two local models:
  - Chat: `qwen3:8b` (or another Ollama chat model)
  - Embeddings: `nomic-embed-text`

## Quick demo (no model required)

From this directory in PowerShell:

```powershell
python -m logwatch_agent replay --log .\demo\sample.log --alerts .\demo-alerts.jsonl
```

Three or more firewall denies from the same source within 60 seconds produce
one alert. The JSON alert contains the detection rule, severity, source, and
the exact log lines that triggered it. With `--ai`, the alert is written at
once with `"analysis": {"status": "pending"}`, and the explanation follows as a
separate `"record_type": "analysis"` line with the same `alert_id`. Remove `.\demo-alerts.jsonl` before
re-running if you want a fresh report.

## Optional RAG explanations with local Ollama

Install the optional dependency and download the local models:

```powershell
python -m pip install -e ".[rag]"
ollama pull qwen3:8b
ollama pull nomic-embed-text
```

Make sure Ollama is running, then index the included runbook:

```powershell
python -m logwatch_agent index --runbooks .\runbooks
```

Replay the sample and request a local explanation:

```powershell
python -m logwatch_agent replay --log .\demo\sample.log --ai --runbooks .\runbooks --alerts .\demo-alerts.jsonl
```

If runbooks change, rebuild their vector index:

```powershell
python -m logwatch_agent index --runbooks .\runbooks --rebuild
```

On a machine without a supported GPU, the model runs on the CPU and the first
request (which loads the model) can be slow. Allow more time with
`--ollama-timeout 300`. Models stay loaded for 30 minutes after each request.

The Ollama client only permits an HTTP endpoint on loopback. Logs and runbooks
are sent only to that local Ollama service; Ollama model downloads themselves
may require internet access.

## Continuous monitoring

The watcher reads complete newline-terminated entries, saves its file cursor
and emitted alert IDs in SQLite, and resumes from that cursor on restart:

```powershell
python -m logwatch_agent watch --log .\path\to\firewall.log --state-dir .\.state
```

Add `--ai` to enrich detected alerts. Use `Ctrl+C` to stop. For a live demo,
append lines from another PowerShell window:

```powershell
Get-Content .\demo\sample.log -Wait | Add-Content .\live-demo.log
```

Alternatively, copy the demo lines into a new log file, then append additional
`DENY` entries with ISO timestamps. The default deny rule triggers at three
matching entries within 60 seconds. The authentication-failure rule triggers
at five matching entries within 60 seconds. Both thresholds are explicit in
`logwatch_agent/core.py`.

## Containerlab environment

[lab/README.md](lab/README.md) describes a Containerlab network (two FRR
routers, an nftables firewall, an nginx web server, clients and an rsyslog
collector) that produces real logs, plus a systemd service that runs the agent
continuously against them.

## Demo flow

1. Explain the fictional topology: a client network, edge firewall, and HTTPS
   server using reserved documentation IP ranges.
2. Replay `demo/sample.log`; show normal `ALLOW` events followed by a burst of
   denied connections from one client.
3. Inspect the alert's supporting lines and the exact threshold rule.
4. Optionally rerun with `--ai`; show which runbook file was retrieved and the
   model's cautious explanation.
5. Point out that the system recommends checks but never applies a fix.

## Current scope and limitations

- Supports appended local text files and ISO-8601 or common RFC3164-style
  syslog prefixes. It is not yet a network Syslog receiver.
- Basic polling notices truncation and replacement of a file at the same path.
  Events written to a rotated-away file between polls may be missed; production
  ingestion should use a dedicated collector/queue.
- Default rules are simple thresholds, not a trained anomaly model. Tune them
  to the environment before relying on alerts.
- The demo runbook and logs are synthetic. They demonstrate plumbing, not
  validated operational recommendations.
- LLM explanations can be wrong. Treat them as suggestions; review cited log
  evidence and runbook sections.
- No command execution, automatic remediation, authentication, web dashboard,
  multi-user support, or production high-availability is included.

## Tests

Run the standard-library unit tests:

```powershell
python -m unittest discover -s tests -v
```

Tests do not require Ollama or ChromaDB and do not access a network.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, the branch and
pull-request workflow, and the design rules the project relies on.
