#!/usr/bin/env bash
# 09 - Transition mechanisms: how IPv6 coexists with / tunnels over IPv4.
# usage: ./09-transition-mechanisms.sh
set -euo pipefail
command -v ip >/dev/null || { echo "needs iproute2" >&2; exit 1; }
echo "== the coexistence toolbox =="
cat <<'T'
  dual-stack         run v4 and v6 side by side (the real answer; rest are crutches)
  6to4     2002::/16         embeds a public v4 in the prefix (2002:V4::/48). legacy.
  Teredo   2001:0::/32       v6 over UDP/IPv4 through NAT (old Windows). legacy.
  6in4 / GRE               manual v6-in-v4 tunnel (e.g. HE tunnelbroker)
  NAT64 + DNS64  64:ff9b::/96  v6-only client -> v4 server; DNS64 synthesizes AAAA
  464XLAT                  runs v4 apps on a v6-only mobile network
T
echo
echo "== what's on this host? =="
hits=0
while read -r _ _ _ cidr _; do
  a="${cidr%/*}"
  case "$a" in
    2002:*)    echo "  $a  -> 6to4 (decode embedded v4: sixctl explain $a)"; hits=1 ;;
    2001:0:*)  echo "  $a  -> Teredo"; hits=1 ;;
    64:ff9b:*) echo "  $a  -> NAT64 well-known prefix"; hits=1 ;;
    ::ffff:*)  echo "  $a  -> IPv4-mapped"; hits=1 ;;
  esac
done < <(ip -6 -o addr show 2>/dev/null)
if ip -6 tunnel show 2>/dev/null | grep -q .; then echo "  tunnels:"; ip -6 tunnel show 2>/dev/null | sed 's/^/    /'; hits=1; fi
[[ "$hits" == 0 ]] && echo "  none - looks like native dual-stack or v6-only (the good case)."
echo
echo "decode any embedded-v4 address with:  sixctl explain <addr>"
