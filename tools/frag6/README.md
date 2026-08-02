# frag6

Hand-crafts IPv6 atomic and overlapping fragments from raw Ethernet
frames up - no libpcap, no scapy, no libnet, just `AF_PACKET` and hand-rolled
wire-format structs. Resolves the destination's link-layer address
itself via a real Neighbor Solicitation/Advertisement exchange unless
you pass `--dst-mac`.

Two distinct, RFC-documented fragmentation hazards:

- **atomic** ([RFC 6946](https://www.rfc-editor.org/rfc/rfc6946)) - a
  single packet carrying a Fragment header (Next Header 44) that isn't
  actually fragmented (offset 0, M=0). Some stateless filters treat
  "has a fragment header" as "can't fully inspect this," even though
  the packet is complete and fully parseable.
- **overlap** ([RFC 5722](https://www.rfc-editor.org/rfc/rfc5722)) -
  two fragments that both claim byte range `[0, frag-size)`: a decoy
  (M=1, "more data follows") and the real, complete payload (M=0,
  "this is everything"). A spec-compliant stack must discard the whole
  reassembled datagram the instant it detects overlapping fragments -
  so running this against a compliant target should deliver nothing at
  all. Anything a target *does* deliver (decoy, real, or a splice of
  both) means it isn't RFC 5722-compliant. Background: Antonios
  Atlasis, "Attacking IPv6 Implementation Using Fragmentation" (2012).

Real-interface capable, like the rest of this repo's arsenal (see the
authorization banner in the [repo README](../../README.md)). Pairs with
[`demos/10-attack-lab`](../../demos/10-attack-lab) (which has a
quick-iteration scapy version of the same two techniques,
`03-fragmentation-abuse.py`) and the fragmentation-abuse section of
`demos/11-firewalling.sh`.

## Build

```bash
gcc -O2 -Wall -o frag6 frag6.c
```

No dependencies beyond libc.

## Usage

```bash
sudo ./frag6 --iface eth0 --dst fd00::2 --mode atomic --payload icmp6-echo
sudo ./frag6 --iface eth0 --dst fd00::2 --mode overlap --frag-size 8
sudo ./frag6 --iface eth0 --dst fd00::2 --dst-mac aa:bb:cc:dd:ee:ff --mode atomic
sudo ./frag6 --iface eth0 --dst fd00::2 --mode atomic --raw-payload deadbeefcafe0102 --next-header 17
```

Run `./frag6 --help` for the full flag list.

## Requirements

- Linux, a C toolchain (`gcc`/`clang`)
- Root / `CAP_NET_RAW` (opens an `AF_PACKET` raw socket)
