#!/usr/bin/env bash
# 12 - Capstone: a guided read-only tour that runs the whole arc in order.
# usage: ./12-capstone.sh [interface]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
iface="${1:-}"
run() {
  local f="$1"; shift
  echo; echo "############################################################"
  echo "# $f"
  echo "############################################################"
  if [[ -x "$here/$f" ]]; then bash "$here/$f" "$@"; else echo "(missing: $f)"; fi
}
echo "IPv6 from the ground up - a read-only tour. Every step is a standalone demo;"
echo "this just walks them in teaching order. Offensive view is demos/10-attack-lab/."
run 01-address-anatomy.sh ${iface:+"$iface"}
run 02-slaac.sh ${iface:+"$iface"}
run 03-ndp.sh ${iface:+"$iface"}
run 04-router-advertisement.sh ${iface:+"$iface"}
run 05-icmpv6.sh
run 07-multicast.sh ${iface:+"$iface"}
run 08-dhcpv6.sh ${iface:+"$iface"}
run 09-transition-mechanisms.sh
run 11-firewalling.sh
echo; echo "that's the stack. tooling next:  tools/sixctl (explain, scan)  tools/frag6"
