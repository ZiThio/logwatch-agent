#!/usr/bin/env bash
# Installs the LogWatch agent as a systemd user service that watches the lab
# logs continuously, starts at boot, and restarts itself if it stops.
# Run from anywhere inside the repository, after creating .venv (see README).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
UNIT_DIR="$HOME/.config/systemd/user"
PYTHON="$REPO/.venv/bin/python"

if [ ! -x "$PYTHON" ]; then
    echo "Virtual environment not found at $REPO/.venv; create it first." >&2
    exit 1
fi

mkdir -p "$UNIT_DIR"
cat > "$UNIT_DIR/logwatch-agent.service" <<EOF
[Unit]
Description=LogWatch Agent - continuous monitoring of the Containerlab logs
After=ollama-tunnel.service
Wants=ollama-tunnel.service

[Service]
WorkingDirectory=$REPO
ExecStart=$PYTHON -m logwatch_agent watch --log lab/logs/all.log --alerts lab/alerts.jsonl --state-dir .state --ai --runbooks runbooks --ollama-timeout 300
# Retry if the lab is not running yet (log file missing) or Ollama is unreachable.
Restart=on-failure
RestartSec=15
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now logwatch-agent
loginctl enable-linger "$USER"
echo "Installed. Follow it with: journalctl --user -u logwatch-agent -f"
