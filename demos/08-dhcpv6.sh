#!/usr/bin/env bash
# 08 - DHCPv6
#
# purpose: contrast stateful DHCPv6 (server hands out the address) with
#          stateless DHCPv6 (SLAAC handles the address, DHCPv6 only hands
#          out DNS/NTP/etc), and show the M/O flag combination that
#          triggers each from the RA
# prereqs: root, isc-dhcp-server or kea-dhcp6, radvd for the RA side
# planned commands:
#   dhclient -6 <iface>                    # request a lease
#   journalctl -u isc-dhcp-server6 -f      # watch the exchange server-side
#   see cheatsheet.md's SLAAC vs DHCPv6 table for the M/O flag matrix

set -euo pipefail
echo "not yet implemented"
