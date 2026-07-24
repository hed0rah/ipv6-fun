#!/usr/bin/env bash
# 07 - multicast
#
# purpose: show why IPv6 has no broadcast - solicited-node multicast
#          groups, joining/leaving via MLD, and how MLD snooping keeps a
#          switch from flooding every NDP packet to every port
# prereqs: root
# planned commands:
#   ip maddr show                         # multicast group membership per iface
#   ping6 -c3 ff02::1%<iface>              # all-nodes
#   ping6 -c3 ff02::2%<iface>              # all-routers
#   tcpdump -i <iface> icmp6 and ip6[40] == 130  # MLD queries

set -euo pipefail
echo "not yet implemented"
