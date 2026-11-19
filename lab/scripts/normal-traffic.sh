#!/usr/bin/env bash
# Legitimate traffic: client1 browses the web server and logs in correctly.
# This produces ALLOW-type activity and access logs, but no alerts.
set -euo pipefail

CLIENT=clab-logwatch-client1
WEB=198.51.100.20
COUNT=${1:-5}

for i in $(seq 1 "$COUNT"); do
    docker exec "$CLIENT" curl -s -o /dev/null -w "client1 GET /        -> %{http_code}\n" "http://$WEB/"
    docker exec "$CLIENT" curl -s -o /dev/null -w "client1 GET /admin/  -> %{http_code}\n" \
        -u admin:labpass123 "http://$WEB/admin/"
    sleep 2
done
