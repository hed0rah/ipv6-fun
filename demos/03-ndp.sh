#!/usr/bin/env bash
# 03 - Neighbor Discovery Protocol
#
# purpose: watch Neighbor Solicitation/Advertisement resolve an address
#          (the ARP replacement) and watch Duplicate Address Detection
#          reject a colliding address
# prereqs: root, two hosts/netns on the same link, ndisc6 suite recommended
# planned commands:
#   ip -6 neigh show                      # neighbor cache: INCOMPLETE/STALE/REACHABLE
#   ndisc6 <target-addr> <iface>          # manually trigger NS, show NA
#   tcpdump -i <iface> icmp6              # watch NS/NA on the wire
#   ip -6 addr add <dup-addr>/64 dev <iface>  # trigger DAD against a live address

set -euo pipefail
echo "not yet implemented"
