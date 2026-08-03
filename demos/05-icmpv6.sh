#!/usr/bin/env bash
# 05 - ICMPv6: not optional like ICMPv4 - NDP, MLD, PMTUD and errors all ride it.
# usage: ./05-icmpv6.sh [target]   (default: ::1, then the default gateway)
set -euo pipefail
command -v ping >/dev/null || { echo "needs iputils ping" >&2; exit 1; }
echo "== ICMPv6 message types (RFC 4443 + friends) =="
cat <<'T'
  errors:   1 destination-unreachable   2 packet-too-big (drives PMTUD)
            3 time-exceeded             4 parameter-problem
  info:   128 echo-request           129 echo-reply        (this is ping)
  NDP:    133 router-solicit  134 router-advert  135 neighbor-solicit
          136 neighbor-advert 137 redirect
  MLD:    130 query  131 report  132 done        (multicast membership)
T
echo
echo "unlike ICMPv4 you CANNOT drop ICMPv6 wholesale - block type 134/135 and the"
echo "network stops working (no RAs, no neighbor resolution). See 11-firewalling.sh."
echo
echo "== live echo (types 128/129) =="
if ping -6 -c2 -W1 ::1 >/dev/null 2>&1; then echo "  ::1 (loopback) ... reply"; else echo "  ::1 ... no reply"; fi
tgt="${1:-}"
[[ -z "$tgt" ]] && tgt=$(ip -6 route show default 2>/dev/null | awk '/default via/{print $3"%"$5; exit}')
if [[ -n "$tgt" ]]; then
    if ping -6 -c2 -W1 "$tgt" >/dev/null 2>&1; then echo "  $tgt (gateway) ... reply"; else echo "  $tgt ... no reply"; fi
fi
echo
echo "field-level breakdown: the ICMPv6 anatomy page (icmpv6-anatomy.html)."
