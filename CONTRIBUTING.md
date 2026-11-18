# Contributing to LogWatch Agent

## Development setup

Requires Python 3.10 or later.

```bash
git clone <repository-url>
cd logwatch-agent
python -m venv .venv
# Windows PowerShell:  .\.venv\Scripts\Activate.ps1
# macOS / Linux:       source .venv/bin/activate
python -m pip install -e .
```

The core (replay, watch, rule detection) uses only the standard library.
To work on the optional RAG features, also install ChromaDB and the local
Ollama models:

```bash
python -m pip install -e ".[rag]"
ollama pull qwen3:8b
ollama pull nomic-embed-text
```

## Running the tests

```bash
python -m unittest discover -s tests -v
```

Tests must not require Ollama, ChromaDB, or network access. Mock those
dependencies instead. GitHub Actions runs the suite on Linux and Windows
for every pull request.

## Workflow

1. Create a branch from `main` (for example `feature/syslog-receiver` or
   `fix/rotation-gap`).
2. Keep each change focused, and add or update tests for any behavior change.
3. Run the test suite locally before pushing.
4. Open a pull request that describes what changed and why. At least one
   other collaborator should review it before merging.

Do not push directly to `main`.

## Project layout

| Path | Purpose |
|---|---|
| `logwatch_agent/app.py` | CLI (`replay`, `watch`, `index`) and orchestration |
| `logwatch_agent/core.py` | Log parsing, `DetectionRule` definitions, `RuleDetector` |
| `logwatch_agent/follower.py` | Incremental file reading with rotation/truncation handling |
| `logwatch_agent/state.py` | SQLite cursor and alert de-duplication store |
| `logwatch_agent/ollama.py` | Loopback-only Ollama HTTP client |
| `logwatch_agent/rag.py` | ChromaDB runbook index and AI alert explanation |
| `runbooks/` | Reference documents indexed for RAG (synthetic examples) |
| `demo/` | Synthetic sample logs |
| `tests/` | Standard-library `unittest` suite |

## Design rules to keep

- **Detection stays deterministic.** Alerts come from explicit rules in
  `core.py`, never from an LLM. AI output is optional enrichment only.
- **An AI failure must never drop an alert.** The alert is written with an
  `analysis.error` field instead.
- **Ollama stays loopback-only.** Logs and runbooks must not be sent to a
  remote service.
- **No command execution or automatic remediation.** The tool suggests checks;
  a human applies changes.
- **Log lines and runbook text are untrusted input**, both for parsing and in
  LLM prompts.

## Data hygiene

Do not commit real logs, real IP addresses, credentials, or generated state
(`.state/`, `alerts.jsonl`). Use reserved documentation ranges such as
`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` in examples and tests.
