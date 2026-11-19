# LogWatch Containerlab environment

A small network that produces real router, firewall and web server logs,
collects them centrally, and lets the LogWatch agent monitor them
continuously.

```
 client1 (192.0.2.2) ─┐
                      ├─ router1 ══ OSPF ══ router2 ── web (198.51.100.20)
attacker (192.0.2.18)─┘  firewall  10.0.12.0/30        nginx

 all nodes ── management network 172.20.20.0/24 ── syslog (172.20.20.50)
                                                     │
                                          lab/logs/all.log
                                                     │
                                          LogWatch agent (systemd service)
                                                     │
                                          Ollama on the Windows host (SSH tunnel)
```

| Node | Image | Role |
|---|---|---|
| `router1` | `logwatch/router:lab` (Debian, FRR, nftables, ulogd2, rsyslog) | Edge router and firewall; logs every denied connection as `FW-DENY ...` |
| `router2` | `logwatch/router:lab` | Server-side router; OSPF neighbor of router1 |
| `client1` | `logwatch/host:lab` (Alpine) | Legitimate user |
| `attacker` | `logwatch/host:lab` | Generates suspicious traffic, inside the lab only |
| `web` | `nginx:1.27-alpine` | Web server; `/admin/` needs a password (lab-only: `admin` / `labpass123`) |
| `syslog` | `logwatch/syslog:lab` (rsyslog) | Central log receiver; writes `lab/logs/all.log` |

**Firewall policy (router1):** `192.0.2.0/24` may reach `198.51.100.20` on
TCP 80 and 443. All other forwarded traffic is dropped and logged.

All addresses come from ranges reserved for documentation. Run the attack
script only against this lab.

## Prerequisites (Ubuntu VM)

1. Docker and Containerlab:
   ```bash
   sudo apt install -y docker.io
   sudo usermod -aG docker $USER        # then log out and back in
   bash -c "$(curl -sL https://get.containerlab.dev)"
   ```
2. The agent installed in `.venv` with the RAG extra, and the Ollama SSH tunnel
   running (see the main README).

## 1. Build the images

```bash
bash lab/scripts/build-images.sh
```

## 2. Start the lab

```bash
sudo containerlab deploy -t lab/logwatch.clab.yml
```

Check it:

```bash
sudo containerlab inspect -t lab/logwatch.clab.yml        # all nodes "running"
docker exec clab-logwatch-router1 vtysh -c "show ip ospf neighbor"   # router2 "Full"
docker exec clab-logwatch-client1 curl -s -o /dev/null -w "%{http_code}\n" http://198.51.100.20/   # 200
tail -n 5 lab/logs/all.log                                 # log lines are arriving
```

## 3. Start continuous monitoring

```bash
bash lab/scripts/install-monitor.sh
```

This installs a systemd user service, `logwatch-agent`, that watches
`lab/logs/all.log`, writes alerts to `lab/alerts.jsonl`, explains them with
Ollama, starts at boot and restarts itself after a failure (for example, while
the lab is not running yet). Follow it live:

```bash
journalctl --user -u logwatch-agent -f
```

Pick up a code or runbook change with `systemctl --user restart logwatch-agent`.
After adding or editing a runbook, rebuild the index first:
`.venv/bin/python -m logwatch_agent index --runbooks runbooks --rebuild`.

## 4. Generate traffic

```bash
bash lab/scripts/normal-traffic.sh          # legitimate requests: no alert expected
bash lab/scripts/attack.sh firewall         # blocked SSH attempts -> firewall-deny-burst
bash lab/scripts/attack.sh auth             # wrong passwords -> authentication-failure-burst
```

Each rule fires at most once every 5 minutes for the same source, so wait
before repeating a scenario. Alerts appear in the service log and in
`lab/alerts.jsonl`:

```bash
tail -n 1 lab/alerts.jsonl | python3 -m json.tool
```

## 5. Stop

```bash
sudo containerlab destroy -t lab/logwatch.clab.yml
systemctl --user stop logwatch-agent       # optional; otherwise it waits for the next lab
```

`lab/logs/all.log` is kept between runs. Delete it (it belongs to root:
`sudo rm lab/logs/all.log`) together with `.state/monitor.sqlite3` to start
from scratch.

## Troubleshooting

| Symptom | Check |
|---|---|
| `lab/logs/all.log` missing or empty | `docker logs clab-logwatch-syslog`; the collector must be running at 172.20.20.50 |
| No `FW-DENY` lines after `attack.sh firewall` | `docker exec clab-logwatch-router1 nft list ruleset` and `docker exec clab-logwatch-router1 pgrep -a ulogd` |
| Port 22 reported open | The firewall rules did not load; rerun `docker exec clab-logwatch-router1 sh /usr/local/bin/lab-start` and read its errors |
| Client gets no answer from the web server | OSPF: `docker exec clab-logwatch-router1 vtysh -c "show ip route"` |
| `ip addr add` fails with "Operation not permitted" | The node is not privileged; check your Containerlab version's defaults |
| Alerts have `"error": "AI explanation unavailable"` | `curl http://127.0.0.1:11434/api/tags` (SSH tunnel) |
| Service keeps restarting | `journalctl --user -u logwatch-agent -n 30` |

## Next steps

- Add a detection rule for OSPF neighbor loss (FRR logs `ADJCHANGE` lines).
- Add an HTTP-error-burst rule from the nginx access log (many 401/403/404).
