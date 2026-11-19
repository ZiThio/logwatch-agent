# Firewall deny bursts

## Expected policy

The demo web service is `198.51.100.20` and accepts HTTP and HTTPS on TCP
ports 80 and 443. The client network is `192.0.2.0/24`. The edge firewall
(router1) allows only that traffic to the web service and denies and logs
everything else, including SSH (TCP 22). These addresses are reserved for
examples and do not identify real hosts.

## Investigate repeated denies

1. Confirm the source address, destination address, destination port, and time
   range from the firewall logs.
2. Check whether the deny entries match the intended policy and whether a
   corresponding allow rule exists for the approved client network.
3. Check routing and service availability independently before attributing the
   incident to the firewall.
4. Have an authorized operator review any proposed policy change. Do not make
   broad allow rules as a troubleshooting shortcut.

## Evidence and limits

A `DENY` log entry shows that a logged connection attempt was denied. By itself,
it does not establish user impact, the intended policy, or the root cause.
Correlate timestamps and endpoints with other approved sources before acting.
