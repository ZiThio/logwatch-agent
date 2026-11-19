# Central log receiver. The configuration is mounted from lab/configs/syslog.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends rsyslog \
    && rm -rf /var/lib/apt/lists/*

CMD ["rsyslogd", "-n", "-f", "/etc/rsyslog.conf"]
