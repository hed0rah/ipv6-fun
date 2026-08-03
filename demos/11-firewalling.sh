#!/usr/bin/env bash
# 11 - Firewalling: no NAT in IPv6, so the firewall IS the perimeter.
# Read-only review of the v6 ruleset. usage: ./11-firewalling.sh
set -euo pipefail
echo "== the IPv6 firewall mindset =="
echo "no NAT means every host is globally routable and reachable UNLESS a firewall"
echo "says no - nothing is accidentally hidden. So input/forward chains ARE the"
echo "perimeter: default-deny inbound, allow only what you mean to expose. And never"
echo "blanket-drop ICMPv6 (kills RAs + neighbor resolution) - see 05-icmpv6.sh."
echo
printf "== forwarding (is this box a router?) ==\n  net.ipv6.conf.all.forwarding = %s\n" \
  "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo '?')"
echo
if command -v nft >/dev/null && nft list ruleset >/dev/null 2>&1; then
  echo "== nftables (inet/ip6 tables, chain policies, icmpv6 rules) =="
  nft list ruleset 2>/dev/null | grep -iE 'table (inet|ip6)|chain (input|forward|output)|policy |icmpv6|ct state' | sed 's/^/  /' | head -40
elif command -v ip6tables >/dev/null && ip6tables -S >/dev/null 2>&1; then
  echo "== ip6tables (policies + rules) =="
  ip6tables -S 2>/dev/null | sed 's/^/  /' | head -40
else
  echo "  (no readable v6 ruleset - need root, or none configured)"
fi
echo
echo "audit lens: every inbound 'accept' to a host = that host is exposed on the"
echo "internet (no NAT to hide behind). Cross-check against your shields toolkit."
