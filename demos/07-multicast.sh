#!/usr/bin/env bash
# 07 - Multicast: IPv6 leans on it heavily - there is no broadcast at all.
# usage: ./07-multicast.sh [interface]
set -euo pipefail
command -v ip >/dev/null || { echo "needs iproute2 (Linux)" >&2; exit 1; }
iface="${1:-}"
echo "== well-known IPv6 multicast groups =="
cat <<'G'
  ff02::1            all-nodes on the link       (the v6 'broadcast')
  ff02::2            all-routers on the link
  ff02::1:ffXX:XXXX  solicited-node (NDP)        (one per unicast, low 24 bits)
  ff02::fb           mDNS          ff02::1:2     all DHCP relays/servers
  scope digit in ff0X::  1 interface  2 link  5 site  8 org  e global
G
echo
echo "== groups this host has joined (ip maddr) =="
mg=$(ip maddr show ${iface:+dev "$iface"} 2>/dev/null | awk '/inet6/{print "  "$2}' | sort -u || true)
if [[ -z "$mg" ]]; then echo "  (none shown)"; else printf '%s\n' "$mg"; fi
echo
echo "membership is announced with MLD (ICMPv6 130/131/132), the v6 IGMP. Every"
echo "unicast address auto-joins its solicited-node group so NDP can reach it"
echo "without waking the whole segment the way ARP broadcast does."
[[ -n "$iface" ]] && echo "see who answers all-nodes:  ping -6 ff02::1%$iface"
