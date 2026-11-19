#!/bin/sh
# Starts the router services. Run once by Containerlab after the links exist.
set -e

sysctl -w net.ipv4.ip_forward=1

# Forward local syslog (FRR, ulogd) to the collector first, so nothing is lost.
# The config is mounted at the default path, /etc/rsyslog.conf (see topology).
rsyslogd

# Only router1 has a firewall configuration.
if [ -f /etc/nftables-lab.nft ]; then
    nft -f /etc/nftables-lab.nft
    # The ulogd plugin directory depends on the CPU architecture; find it.
    plugin=$(find /usr/lib -name ulogd_inppkt_NFLOG.so | head -n 1)
    sed "s#@PLUGDIR@#$(dirname "$plugin")#g" /etc/ulogd-lab.conf.in > /etc/ulogd-lab.conf
    ulogd -d -c /etc/ulogd-lab.conf
fi

/usr/lib/frr/frrinit.sh start
