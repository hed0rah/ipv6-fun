#!/usr/bin/env bash
# 09 - transition mechanisms
#
# purpose: stand up a 6to4 or NAT64/DNS64 path just far enough to see why
#          these exist and why native dual-stack made most of them obsolete
# prereqs: root, a NAT64 implementation (e.g. tayga) or public 6to4 relay
#          for the historical demo
# planned commands:
#   ip tunnel add tun6to4 mode sit remote any local <v4-addr>  # 6to4, historical
#   tayga --config /etc/tayga.conf                              # NAT64
#   dig AAAA <v4-only-host> @<dns64-resolver>                    # DNS64 synth

set -euo pipefail
echo "not yet implemented"
