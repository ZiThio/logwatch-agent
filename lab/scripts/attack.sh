#!/usr/bin/env bash
# Simulated suspicious activity from the attacker host, inside the lab only.
#   firewall  - connection attempts to a port the firewall blocks (SSH, 22)
#               -> "firewall-deny-burst" alert (3 denies within 60 s)
#   auth      - wrong passwords on the protected web page
#               -> "authentication-failure-burst" alert (5 failures within 60 s)
# Usage: attack.sh [firewall|auth|all]   (default: all)
set -euo pipefail

ATTACKER=clab-logwatch-attacker
WEB=198.51.100.20
SCENARIO=${1:-all}

firewall() {
    echo "== Blocked connection attempts to $WEB:22"
    for i in $(seq 1 5); do
        docker exec "$ATTACKER" nc -z -w 1 "$WEB" 22 \
            && echo "attempt $i: port open (unexpected: check the firewall)" \
            || echo "attempt $i: blocked"
    done
}

auth() {
    echo "== Wrong passwords on http://$WEB/admin/"
    for password in 123456 password admin letmein qwerty welcome; do
        docker exec "$ATTACKER" curl -s -o /dev/null -w "admin:$password -> %{http_code}\n" \
            -u "admin:$password" "http://$WEB/admin/"
    done
}

case "$SCENARIO" in
    firewall) firewall ;;
    auth) auth ;;
    all) firewall; auth ;;
    *) echo "usage: $0 [firewall|auth|all]" >&2; exit 2 ;;
esac
