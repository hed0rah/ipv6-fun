#!/usr/bin/env bash
# 02 - SLAAC
#
# purpose: watch a new IPv6 address get born from a router advertisement,
#          compare EUI-64 vs RFC 4941 privacy-extension address generation
# prereqs: root, an interface with an IPv6 router on the link (or run
#          demos/04-router-advertisement.sh's RA sender against a netns pair)
# planned commands:
#   sysctl net.ipv6.conf.<iface>.use_tempaddr   # 0=EUI-64 only, 2=prefer privacy
#   ip -6 addr show dev <iface>                  # watch mngtmpaddr / tentative flags
#   ip -6 addr flush dev <iface> && ip link set <iface> down/up  # force re-SLAAC

set -euo pipefail
echo "not yet implemented"
