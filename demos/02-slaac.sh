#!/usr/bin/env bash
# 02 - SLAAC (Stateless Address Autoconfiguration)
#
# how a host mints its own global IPv6 address from a Router Advertisement,
# with no DHCP server involved. Read-only by default: it inspects the SLAAC
# state your kernel already built, and points out EUI-64 (MAC-derived, guessable)
# vs privacy/temporary addresses.
#
# usage: ./02-slaac.sh [interface]
#        ./02-slaac.sh --reslaac <interface>   # actively re-trigger (disruptive)
#
# --reslaac flushes global addrs and bounces the link, so the kernel re-runs
# SLAAC from scratch. It DROPS any connection routed over that interface - never
# run it over SSH on the same interface.

set -euo pipefail

need() { command -v "$1" >/dev/null 2>&1 || { echo "needs '$1' (Linux / iproute2)" >&2; exit 1; }; }
need ip
need sysctl

mode="show"
if [[ "${1:-}" == "--reslaac" ]]; then mode="reslaac"; shift; fi

iface="${1:-}"
if [[ -z "$iface" ]]; then
    iface=$(ip -6 -o addr show scope global 2>/dev/null | awk '$2!="lo"{print $2; exit}')
fi
if [[ -z "$iface" ]]; then
    echo "no interface with a global IPv6 address found - pass one explicitly" >&2
    exit 1
fi

echo "== SLAAC on $iface =="
echo "the host hears a Router Advertisement carrying a /64 prefix flagged 'A'"
echo "(autonomous), and forms its own address = prefix + interface-ID. No DHCP"
echo "server. The kernel does it automatically when accept_ra and autoconf are on."
echo

gets() { sysctl -n "net.ipv6.conf.$iface.$1" 2>/dev/null || echo "?"; }
echo "== kernel knobs =="
printf "  accept_ra    = %s   (0 off | 1 on | 2 on even when forwarding)\n" "$(gets accept_ra)"
printf "  autoconf     = %s   (1 = build SLAAC addresses from RA prefixes)\n" "$(gets autoconf)"
printf "  use_tempaddr = %s   (0 EUI-64 only | 2 prefer RFC 4941/8981 privacy temp addrs)\n" "$(gets use_tempaddr)"
echo

echo "== default route (learned from the RA, not configured) =="
if ip -6 route show default dev "$iface" 2>/dev/null | grep -q .; then
    ip -6 route show default dev "$iface" | sed 's/^/  /'
    echo "  (a default via a fe80:: address = it came from a Router Advertisement)"
else
    echo "  (none on this iface)"
fi
echo

echo "== global addresses SLAAC produced on $iface =="
found=0
while read -r _ _ _ cidr rest; do
    addr="${cidr%/*}"
    found=1
    if printf '%s' "$addr" | grep -qi 'ff:fe'; then
        tell="EUI-64: your MAC is baked in (the ff:fe tell) - host bits guessable"
    else
        tell="opaque IID: random / stable-privacy / temporary - good"
    fi
    if printf '%s' "$rest" | grep -qi 'temporary'; then
        tell="$tell  [privacy temp addr]"
    fi
    printf "  %s\n      %s\n" "$addr" "$tell"
done < <(ip -6 -o addr show dev "$iface" scope global)
[[ "$found" == 0 ]] && echo "  (no global addresses - no RA on this link, or autoconf is off)"
echo
echo "the ff:fe tell is exactly what 'sixctl scan --predict' exploits: an EUI-64"
echo "address leaks the MAC, collapsing 2^64 host bits to a guessable ~24. Privacy"
echo "temporary addresses (use_tempaddr=2) hide the MAC and rotate - prefer them."
echo "decode any address fully with:  sixctl explain <addr>"

if [[ "$mode" == "reslaac" ]]; then
    echo
    echo "== --reslaac: forcing re-SLAAC on $iface =="
    echo "!! this flushes global addresses and bounces the link. You WILL drop any"
    echo "   connection routed over $iface. Do NOT run this over SSH on $iface."
    read -r -p "type YES to proceed: " ans
    if [[ "$ans" != "YES" ]]; then echo "aborted."; exit 0; fi
    sudo ip -6 addr flush dev "$iface" scope global
    sudo ip link set "$iface" down
    sudo ip link set "$iface" up
    echo "link bounced; the kernel re-solicits an RA and rebuilds SLAAC addresses"
    echo "(they appear 'tentative' during DAD, then become valid):"
    sleep 3
    ip -6 -o addr show dev "$iface" scope global | sed 's/^/  /'
fi
