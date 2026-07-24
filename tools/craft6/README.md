# craft6

Raw-socket C tool, no dependencies beyond libc, that hand-builds an IPv6
packet: fixed header, an arbitrary extension header chain (hop-by-hop,
routing, fragment, destination options), and an upper-layer payload
(ICMPv6 echo, raw UDP).

Mirrors the "genuinely useful with zero deps" feel of `bpf-fun`'s tools -
where `demos/06-extension-headers.py` uses scapy for fast iteration, this
is the from-scratch version: manual header struct packing, manual
checksum (the IPv6 pseudo-header checksum, since IPv6 itself has no
header checksum), `IPPROTO_RAW`/`SOCK_RAW` sockets.

## Planned interface

```
craft6 --dst fe80::1%eth0 --ext hopbyhop,routing --payload icmp6-echo
craft6 --dst fd00::2 --ext fragment:frag-offset=8,more=1 --raw-payload deadbeef
```

Not yet implemented.
