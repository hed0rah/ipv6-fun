#!/usr/bin/env bash
# 04 - Router Advertisement: how hosts learn the prefix, gateway and M/O/A flags.
# Read-only. If ndisc6's 'rdisc6' is present it solicits + dumps a live RA.
# usage: ./04-router-advertisement.sh [interface]
set -euo pipefail
command -v ip >/dev/null || { echo "needs iproute2 (Linux)" >&2; exit 1; }
iface="${1:-}"
[[ -z "$iface" ]] && iface=$(ip -6 -o addr show scope global 2>/dev/null | awk '$2!="lo"{print $2; exit}')
[[ -z "$iface" ]] && { echo "pass an interface" >&2; exit 1; }

echo "== Router Advertisement on $iface =="
echo "routers multicast RAs to ff02::1 (and answer Router Solicitations). An RA"
echo "carries on-link /64 prefix(es) with the A flag (use for SLAAC), the default-"
echo "router lifetime, MTU, DNS, and the flags:"
echo "  M (managed) = get your ADDRESS from DHCPv6 (stateful)"
echo "  O (other)   = SLAAC for the address, DHCPv6 only for DNS/options"
echo "  neither     = pure SLAAC"
echo
echo "== what this host took from the RA =="
printf "  accept_ra = %s\n" "$(sysctl -n net.ipv6.conf.$iface.accept_ra 2>/dev/null || echo '?')"
echo "  default route learned from RA:"
if ip -6 route show default dev "$iface" 2>/dev/null | grep -q .; then
    ip -6 route show default dev "$iface" | sed 's/^/    /'
else echo "    (none)"; fi
echo "  on-link routes (RA-derived / connected):"
ip -6 route show dev "$iface" 2>/dev/null | grep -vi '^default' | sed 's/^/    /' || true
echo
if command -v rdisc6 >/dev/null; then
    echo "== live RA (rdisc6 solicits and prints the real advertisement) =="
    rdisc6 -1 -w 3000 "$iface" 2>/dev/null | sed 's/^/  /' || echo "  (no RA received in 3s)"
else
    echo "install 'ndisc6' to get rdisc6, which solicits and prints the raw RA fields."
fi
echo "sending your OWN RA is a rogue-RA attack - do it in an isolated netns:"
echo "see demos/10-attack-lab/01-rogue-ra.py."
