#!/usr/bin/env bash
# =============================================================================
# Attack Lab Sandbox - two network namespaces, one veth cable between them
# =============================================================================
# Builds the throwaway L2 segment every script in this directory runs
# against: v6lab-victim and v6lab-attacker, joined by a single veth pair
# (same pattern as namespaces-fun's demo 03 - a veth pair IS a full
# Ethernet link, multicast and all, so NDP/RA traffic behaves exactly
# like it would on a real LAN).
#
# Unlike the course demos elsewhere in this repo, this script does NOT
# tear itself down on exit - it's infrastructure the other scripts in
# this directory need already running. Run ./teardown.sh when you're
# done with the lab.
#
# Run: sudo ./lab-setup.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RESET='\033[0m'

NS_VICTIM="v6lab-victim"
NS_ATTACKER="v6lab-attacker"
VETH_VICTIM="veth-victim"
VETH_ATTACKER="veth-attacker"
PREFIX="fd00:6:cafe::"
VICTIM_ADDR="${PREFIX}2/64"
ATTACKER_ADDR="${PREFIX}3/64"

echo -e "${CYAN}=== Attack Lab Sandbox ===${RESET}"
echo ""

echo -e "${CYAN}[1] Clearing any previous lab state (idempotent)...${RESET}"
ip netns del "$NS_VICTIM" 2>/dev/null || true
ip netns del "$NS_ATTACKER" 2>/dev/null || true
ip link del "$VETH_VICTIM" 2>/dev/null || true
echo -e "${GREEN}    Clean.${RESET}"
echo ""

echo -e "${CYAN}[2] Creating namespaces...${RESET}"
ip netns add "$NS_VICTIM"
ip netns add "$NS_ATTACKER"
echo -e "${GREEN}    $NS_VICTIM, $NS_ATTACKER${RESET}"
echo ""

echo -e "${CYAN}[3] Creating a veth pair - one virtual cable between them...${RESET}"
ip link add "$VETH_VICTIM" type veth peer name "$VETH_ATTACKER"
ip link set "$VETH_VICTIM" netns "$NS_VICTIM"
ip link set "$VETH_ATTACKER" netns "$NS_ATTACKER"
echo -e "${GREEN}    $VETH_VICTIM (in $NS_VICTIM) <====cable====> $VETH_ATTACKER (in $NS_ATTACKER)${RESET}"
echo ""

echo -e "${CYAN}[4] Bringing interfaces up, disabling forwarding so accept_ra applies...${RESET}"
ip netns exec "$NS_VICTIM" ip link set lo up
ip netns exec "$NS_VICTIM" ip link set "$VETH_VICTIM" up
ip netns exec "$NS_VICTIM" sysctl -qw net.ipv6.conf."$VETH_VICTIM".forwarding=0
ip netns exec "$NS_VICTIM" sysctl -qw net.ipv6.conf."$VETH_VICTIM".accept_ra=1
ip netns exec "$NS_VICTIM" sysctl -qw net.ipv6.conf."$VETH_VICTIM".autoconf=1

ip netns exec "$NS_ATTACKER" ip link set lo up
ip netns exec "$NS_ATTACKER" ip link set "$VETH_ATTACKER" up
echo -e "${GREEN}    Done.${RESET}"
echo ""

echo -e "${CYAN}[5] Assigning baseline static addressing...${RESET}"
echo -e "    (this stands in for 'a real network already configured by a"
echo -e "     legitimate router' - the attack scripts add illegitimate"
echo -e "     traffic on top of this, they don't need to bootstrap it)"
ip netns exec "$NS_VICTIM" ip -6 addr add "$VICTIM_ADDR" dev "$VETH_VICTIM"
ip netns exec "$NS_ATTACKER" ip -6 addr add "$ATTACKER_ADDR" dev "$VETH_ATTACKER"
echo -e "${GREEN}    victim:   ${PREFIX}2/64${RESET}"
echo -e "${GREEN}    attacker: ${PREFIX}3/64${RESET}"
echo ""

echo -e "${CYAN}[6] Sanity check - victim reachable from attacker?${RESET}"
ip netns exec "$NS_ATTACKER" ping -6 -c 2 -W 1 "${PREFIX}2" | sed 's/^/    /'
echo ""

echo -e "${YELLOW}=== Lab is up ===${RESET}"
echo -e "  Victim:   sudo ip netns exec $NS_VICTIM bash"
echo -e "  Attacker: sudo ip netns exec $NS_ATTACKER bash"
echo ""
echo -e "  Watch the victim's state from another terminal while you attack it:"
echo -e "    ${GREEN}sudo ip netns exec $NS_VICTIM ip -6 addr show dev $VETH_VICTIM${RESET}"
echo -e "    ${GREEN}sudo ip netns exec $NS_VICTIM ip -6 route show${RESET}"
echo -e "    ${GREEN}sudo ip netns exec $NS_VICTIM ip -6 neigh show${RESET}"
echo -e "    ${GREEN}sudo ip netns exec $NS_VICTIM tcpdump -i $VETH_VICTIM -n icmp6${RESET}"
echo ""
echo -e "  Run an attack from the attacker namespace, e.g.:"
echo -e "    ${GREEN}sudo ip netns exec $NS_ATTACKER python3 01-rogue-ra.py --iface $VETH_ATTACKER${RESET}"
echo ""
echo -e "  When done: ${GREEN}sudo ./teardown.sh${RESET}"
