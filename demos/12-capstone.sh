#!/usr/bin/env bash
# 12 - capstone
#
# purpose: build a v6-only network segment from scratch using nothing but
#          what the earlier modules covered - addressing, RA, DNS,
#          firewalling - the "mini-container from scratch" of this repo
# prereqs: root, everything demos 01-11 depend on
# planned shape:
#   1. create a netns pair (borrow the pattern from namespaces-fun demo 03)
#   2. assign ULA addressing, no IPv4 anywhere
#   3. radvd for RA, a v6-only DNS resolver
#   4. ip6tables ruleset from demos/11 locked down to only what's needed
#   5. prove it end-to-end: resolve a name and fetch it over v6-only

set -euo pipefail
echo "not yet implemented"
