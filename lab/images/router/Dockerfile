# Router image: FRR for routing, nftables for the firewall, ulogd2 to turn
# firewall log events (NFLOG) into syslog messages, and rsyslog to forward
# them to the lab collector.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        frr nftables ulogd2 rsyslog iproute2 iputils-ping procps \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i 's/^ospfd=no/ospfd=yes/' /etc/frr/daemons

# Keep the container running; services are started by lab-start (see the topology).
CMD ["sleep", "infinity"]
