#!/usr/bin/env python3
"""06 - Extension Headers: the IPv6 header 'chain' and why it matters for security.

Read-only: builds a chained packet with scapy and shows it (no send, no root).
IPv6 replaced IPv4 options with a linked list of extension headers, each pointing
to the next via its Next Header field. Order is fixed (RFC 8200), and abusing the
chain (oversized / fragmented chains that hide L4) is a classic firewall/IDS
evasion - RFC 7112, and tools/frag6.

    python3 06-extension-headers.py
"""
import sys
try:
    from scapy.compat import raw
    from scapy.layers.inet6 import (
        IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrRouting,
        IPv6ExtHdrFragment, ICMPv6EchoRequest,
    )
except Exception:
    print("this demo needs scapy:  pip install scapy  (or apt install python3-scapy)", file=sys.stderr)
    sys.exit(1)

NH = {0: "Hop-by-Hop", 43: "Routing", 44: "Fragment", 58: "ICMPv6",
      59: "No-Next-Header", 60: "Destination-Options", 6: "TCP", 17: "UDP"}

print("== recommended extension-header order (RFC 8200) ==")
for n in ("Hop-by-Hop", "Destination-Options (pre-Routing)", "Routing", "Fragment",
          "Authentication Header", "ESP", "Destination-Options", "upper layer (TCP/UDP/ICMPv6)"):
    print(f"  -> {n}")

pkt = (IPv6(dst="2001:db8::1") /
       IPv6ExtHdrHopByHop() /
       IPv6ExtHdrRouting() /
       IPv6ExtHdrFragment() /
       IPv6ExtHdrDestOpt() /
       ICMPv6EchoRequest())
raw(pkt)  # force Next Header computation

print("\n== the chain, followed by each Next Header field ==")
for cls in pkt.layers():
    layer = pkt.getlayer(cls)
    nh = getattr(layer, "nh", None)
    name = layer.__class__.__name__
    if nh is not None:
        print(f"  {name:<22} next-header={nh:<3} -> {NH.get(nh, '?')}")
    else:
        print(f"  {name:<22} (upper-layer payload)")

print("\n== scapy's full decode ==")
pkt.show()

print("\nsecurity: a filter must walk the ENTIRE chain to reach the transport header.")
print("Oversized/fragmented chains hide L4 from stateless filters -> RFC 7112 requires")
print("the first fragment to carry the whole header chain. See tools/frag6 for the abuse side.")
