#!/usr/bin/env bash
# 03 - NDP (Neighbor Discovery): IPv6's ARP replacement, over ICMPv6 multicast.
# Read-only cache inspector. --sweep actively solicits the all-nodes group.
# usage: ./03-ndp.sh [interface] [--sweep]
set -euo pipefail
command -v ip >/dev/null || { echo "needs iproute2 (Linux)" >&2; exit 1; }
sweep=0; iface=""
for a in "$@"; do if [[ "$a" == "--sweep" ]]; then sweep=1; else iface="$a"; fi; done

echo "== NDP: how IPv6 finds neighbors (no broadcast ARP) =="
echo "to reach a neighbor a host multicasts a Neighbor Solicitation to the target's"
echo "solicited-node group ff02::1:ffXX:XXXX; the owner replies with a Neighbor"
echo "Advertisement. The same ICMPv6 machinery does DAD (duplicate-address detection)"
echo "and router discovery (RS/RA)."
echo
if [[ "$sweep" == 1 ]]; then
    t="ff02::1"; [[ -n "$iface" ]] && t="ff02::1%$iface"
    echo "== --sweep: soliciting $t to populate the cache =="
    ping -6 -c3 -W1 "$t" >/dev/null 2>&1 || true
fi
echo "== neighbor cache (ip -6 neigh) =="
nc=$(ip -6 neigh show ${iface:+dev "$iface"} || true)
if [[ -z "$nc" ]]; then echo "  (empty - try --sweep, or generate some traffic first)"; else printf '%s\n' "$nc" | sed 's/^/  /'; fi
echo
echo "states: REACHABLE=confirmed  STALE=cached/unverified  PROBE/DELAY=rechecking"
echo "FAILED=no answer.  watch it live:  ip -6 monitor neigh"
