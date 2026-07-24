#!/usr/bin/env bash
# 11 - firewalling
#
# purpose: the ip6tables/nftables gotchas that don't exist in v4 land -
#          which ICMPv6 types must never be blocked, why extension
#          headers break naive stateless filters, and what RA Guard
#          actually protects against (and how it can be evaded, ties
#          back to demos/10-attack-lab)
# prereqs: root, ip6tables or nftables
# planned commands:
#   ip6tables -L -v                                  # inspect current v6 ruleset
#   nft list ruleset
#   ip6tables -A INPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT  # NS must pass
#   see cheatsheet.md's ICMPv6 table for the full must-allow list

set -euo pipefail
echo "not yet implemented"
