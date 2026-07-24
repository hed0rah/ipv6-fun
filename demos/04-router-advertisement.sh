#!/usr/bin/env bash
# 04 - Router Advertisements
#
# purpose: stand up radvd, watch a real RA on the wire, decode the prefix
#          information option and M/O flags, then trigger one on demand
#          with Router Solicitation instead of waiting for the periodic one
# prereqs: root, radvd installed, ndisc6 suite recommended
# planned commands:
#   radvd -C <config> -n                  # foreground, one-shot config
#   rdisc6 <iface>                        # send RS, print the RA response
#   tcpdump -i <iface> icmp6 and ip6[40] == 134   # RA is ICMPv6 type 134
#   sysctl net.ipv6.conf.<iface>.accept_ra

set -euo pipefail
echo "not yet implemented"
