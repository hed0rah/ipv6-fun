#!/usr/bin/env bash
# 01 - address anatomy
#
# lists every IPv6 address on the box and classifies it by scope/type,
# no special privileges required (read-only).
#
# usage: ./01-address-anatomy.sh [interface]

set -euo pipefail

classify() {
    local addr="$1"
    case "$addr" in
        ::1) echo "loopback" ;;
        fe80:*) echo "link-local unicast" ;;
        fc[0-9a-f][0-9a-f]:* | fd[0-9a-f][0-9a-f]:*) echo "unique local (ULA)" ;;
        ff0[0-9a-f]:*) echo "multicast" ;;
        2* | 3*) echo "global unicast (GUA)" ;;
        *) echo "unknown/other" ;;
    esac
}

if ! command -v ip >/dev/null 2>&1; then
    echo "this demo needs iproute2 (the 'ip' command) - Linux only" >&2
    exit 1
fi

iface="${1:-}"
if [[ -n "$iface" ]]; then
    ip_output=$(ip -6 addr show dev "$iface")
else
    ip_output=$(ip -6 addr show)
fi

echo "== IPv6 addresses =="
current_iface=""
while IFS= read -r line; do
    if [[ "$line" =~ ^[0-9]+:\ ([^:@]+) ]]; then
        current_iface="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ inet6\ ([0-9a-fA-F:]+)/([0-9]+)\ scope\ ([a-z]+)(.*) ]]; then
        addr="${BASH_REMATCH[1]}"
        prefix="${BASH_REMATCH[2]}"
        scope="${BASH_REMATCH[3]}"
        flags="${BASH_REMATCH[4]}"
        kind=$(classify "$addr")
        printf "  %-8s %s/%s\n" "$current_iface" "$addr" "$prefix"
        printf "           scope=%s  type=%s%s\n" "$scope" "$kind" "$flags"
    fi
done <<< "$ip_output"

echo
echo "== solicited-node multicast groups (per unicast address) =="
echo "each unicast/anycast address gets a matching ff02::1:ffXX:XXXX group"
echo "built from its low 24 bits - this is how NDP avoids broadcast."
