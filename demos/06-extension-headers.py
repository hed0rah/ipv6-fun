#!/usr/bin/env python3
"""
06 - extension headers

purpose: build an IPv6 packet with a hop-by-hop options header, a routing
         header, and a fragment header by hand with scapy, and watch what
         happens when they're presented out of RFC 8200 order (the classic
         firewall/IDS evasion trick, see cheatsheet.md's header-order table)
prereqs: root, python3-scapy

planned shape:
    from scapy.all import IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, ICMPv6EchoRequest, send

    pkt = IPv6(dst="fe80::1") / IPv6ExtHdrHopByHop() / ICMPv6EchoRequest()
    send(pkt)

    # then swap the header order and compare what the kernel / a sniffer
    # on the other end actually parses
"""

import sys


def main() -> int:
    print("not yet implemented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
