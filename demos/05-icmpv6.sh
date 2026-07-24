#!/usr/bin/env bash
# 05 - ICMPv6
#
# purpose: show how much of IPv6 rides inside ICMPv6 (ping, errors, MLD,
#          all of NDP), and demonstrate why blocking it wholesale at a
#          firewall breaks the network in ways v4 never would
# prereqs: root
# planned commands:
#   ping -6 -c3 ff02::1%<iface>            # echo request/reply, type 128/129
#   ip6tables -A INPUT -p icmpv6 --icmpv6-type 135 -j DROP  # then watch NDP die
#   ip -6 route add unreachable 2001:db8::1  # then ping it, watch type 1
#   see cheatsheet.md for the full ICMPv6 type table

set -euo pipefail
echo "not yet implemented"
