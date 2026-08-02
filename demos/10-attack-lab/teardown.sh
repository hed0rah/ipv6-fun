#!/usr/bin/env bash
# Tears down the attack-lab sandbox created by lab-setup.sh. Idempotent -
# safe to run even if the lab is already partially or fully gone.
#
# Run: sudo ./teardown.sh
set -uo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'

echo -e "${CYAN}[*] Tearing down the attack lab...${RESET}"
ip netns del v6lab-victim 2>/dev/null || true
ip netns del v6lab-attacker 2>/dev/null || true
ip link del veth-victim 2>/dev/null || true
echo -e "${GREEN}[*] Clean.${RESET}"
