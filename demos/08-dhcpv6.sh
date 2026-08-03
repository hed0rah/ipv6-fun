#!/usr/bin/env bash
# 08 - DHCPv6: stateful vs stateless, and why SLAAC often makes it optional.
# usage: ./08-dhcpv6.sh [interface]
set -euo pipefail
command -v ip >/dev/null || { echo "needs iproute2" >&2; exit 1; }
iface="${1:-}"
[[ -z "$iface" ]] && iface=$(ip -6 -o addr show scope global 2>/dev/null | awk '$2!="lo"{print $2; exit}')

echo "== DHCPv6: three ways a host gets configured =="
echo "  pure SLAAC  (RA, no M/O)  address from the RA prefix, DNS from the RA (RDNSS)"
echo "  stateless   (RA sets O)   SLAAC address, DHCPv6 only for DNS/NTP/options"
echo "  stateful    (RA sets M)   DHCPv6 hands out the ADDRESS + options, tracks a lease"
echo
echo "two things that trip up DHCPv4 people: DHCPv6 has NO gateway option (the"
echo "default route ALWAYS comes from the RA), and clients are keyed by a DUID"
echo "(+ IAID), not their MAC."
echo
echo "== does this host appear to use DHCPv6? (heuristic) =="
found=0
while read -r _ _ _ cidr rest; do
  a="${cidr%/*}"
  if printf '%s' "$rest" | grep -qi 'dynamic' && ! printf '%s' "$a" | grep -qi 'ff:fe'; then
    printf "  %-40s %s\n" "$a" "non-EUI-64 dynamic (DHCPv6 or stable-privacy SLAAC)"
    found=1
  fi
done < <(ip -6 -o addr show ${iface:+dev "$iface"} scope global 2>/dev/null)
[[ "$found" == 0 ]] && echo "  (nothing obvious - likely pure SLAAC here)"
echo
echo "== DUID / leases on disk (path varies by client) =="
shown=0
for p in /var/lib/dhcpcd/*.lease6 /var/lib/dhcp/dhclient6*.leases /run/systemd/netif/leases/*; do
  if [[ -e "$p" ]]; then echo "  $p"; grep -aiE 'duid|ia_|iaid|ip6-address|address' "$p" 2>/dev/null | sed 's/^/    /' | head -5; shown=1; fi
done
[[ "$shown" == 0 ]] && echo "  (no DHCPv6 lease files found)"
echo
echo "the M/O flags that decide all this live in the RA - see 04-router-advertisement.sh"
