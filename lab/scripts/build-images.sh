#!/usr/bin/env bash
# Builds the three lab images. Run again after changing a Dockerfile.
set -euo pipefail
cd "$(dirname "$0")/../images"

docker build -t logwatch/router:lab router
docker build -t logwatch/syslog:lab syslog
docker build -t logwatch/host:lab host
docker pull nginx:1.27-alpine

echo "Images ready. Start the lab with: sudo containerlab deploy -t lab/logwatch.clab.yml"
