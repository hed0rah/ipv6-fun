# ipv6-fun

Scripts and tools for going deep on IPv6 - from address anatomy to
neighbor discovery to hand-crafted packets and the attacks that abuse them.

Hosted version: https://hed0rah.github.io/ipv6-fun/ (TODO)

Sibling repos: [namespaces-fun](https://github.com/hed0rah/namespaces-fun),
[bpf-fun](https://github.com/hed0rah/bpf-fun)

## Authorization / safety

This repo includes real, working offensive tooling: rogue router
advertisements, NDP spoofing, fragmentation-based evasion. These tools
are **real-interface capable** - they are not sandboxed to a lab by
default. Only point them at networks and hosts you own or are explicitly
authorized to test. Nothing here does automatic target discovery or mass
scanning on its own.

The `demos/10-attack-lab` module builds on `namespaces-fun`'s network
namespace + veth sandbox so you can run the same attacks against a
throwaway lab with zero blast radius before ever pointing them at
anything real.

## What's Here

```
demos/
├── 01-address-anatomy.sh       address types & scopes - link-local, ULA, GUA, multicast
├── 02-slaac.sh                 SLAAC - EUI-64 vs privacy extensions, watch an address get born
├── 03-ndp.sh                   Neighbor Discovery - NS/NA replacing ARP, DAD
├── 04-router-advertisement.sh  RA/RS - what a router actually tells your host
├── 05-icmpv6.sh                ICMPv6 - the "everything" protocol
├── 06-extension-headers.py     hop-by-hop, routing, fragment, dest options, chain order
├── 07-multicast.sh             solicited-node multicast, MLD, why v6 doesn't broadcast
├── 08-dhcpv6.sh                stateful vs stateless, what SLAAC doesn't cover
├── 09-transition-mechanisms.sh 6to4, NAT64/DNS64, why they're mostly dead now
├── 10-attack-lab/              rogue RA, NDP spoofing, fragmentation attacks (netns sandbox)
├── 11-firewalling.sh           ip6tables/nftables gotchas that don't exist in v4-land
└── 12-capstone.sh              build a v6-only segment from scratch

tools/
├── sixctl/                     flagship CLI - addrs, ndp, ra, scan, craft
├── craft6/                     raw-socket C tool - hand-build header + extension header chains
├── frag6/                      atomic/overlapping fragmentation demo tool
├── ndp_snoop/                  XDP tool - live-decode RS/RA/NS/NA/Redirect on the wire
└── xdp_ra_guard/               XDP tool - drop unauthorized RAs, RFC 7113/6980-aware

cheatsheet.md                   quick reference for IPv6 addressing, commands, ICMPv6 types
deep-dive.md                    IPv6 from zero to packet-crafting, with history & RFC citations
index.html                      interactive IPv4 vs IPv6 header anatomy (GitHub Pages root)
whitepaper.html                 dense reference brief
```

`ndp_snoop` and `xdp_ra_guard` are BCC/XDP tools in the same style as
[bpf-fun](https://github.com/hed0rah/bpf-fun) - see their own READMEs for
usage. Most of `demos/02` onward and both `tools/craft6` and `tools/frag6`
are scaffolded but not yet implemented - this repo fills in incrementally.

## Usage

```bash
chmod +x demos/*.sh tools/sixctl/sixctl

# most demos need root (raw sockets, interface manipulation)
sudo ./demos/01-address-anatomy.sh
```

## sixctl

```bash
sudo cp tools/sixctl/sixctl /usr/local/bin/sixctl

sixctl addrs                 # list & classify addresses on all interfaces
sixctl ndp                   # dump the neighbor cache with scope annotations
sixctl ra sniff|send          # TODO: sniff or send router advertisements
sixctl scan                  # TODO: multicast/NDP-based host enumeration
sixctl craft                 # TODO: interactive header-chain builder
```

## Requirements

- Linux (uses `iproute2`; namespace-based labs need kernel netns support)
- `iproute2` (`ip`)
- Python 3 + `scapy` for the crafting/attack tooling
- A C toolchain (`gcc`/`clang`) for `craft6`/`frag6`
- BCC (`python3-bpfcc` / `bcc-tools`, depending on distro) for `ndp_snoop` and `xdp_ra_guard`
- Root for most demos and all attack/XDP tooling
