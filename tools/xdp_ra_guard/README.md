# xdp_ra_guard

An XDP-based IPv6 Router Advertisement Guard - real, not naive. Drops
Router Advertisements from any MAC address not explicitly allow-listed.

Two things most simple RA Guards skip, both covered in
[deep-dive.md](../../deep-dive.md#firewalling):

1. **Extension header walking.** It walks the IPv6 extension header
   chain (Hop-by-Hop, Routing, Destination Options) looking for ICMPv6,
   instead of only checking the fixed header's Next Header field. A
   guard that only checks the fixed header is exactly what
   [RFC 7113](https://www.rfc-editor.org/rfc/rfc7113) describes being
   evaded by burying the RA behind an extension header.
2. **Fragmentation.** It drops fragmented traffic headed for a multicast
   or link-local destination outright, rather than attempting
   reassembly. Per [RFC 6980](https://www.rfc-editor.org/rfc/rfc6980),
   legitimate Neighbor Discovery messages are always small enough to
   never need fragmentation - a fragmented ND-shaped packet is itself
   the attack, not something worth reassembling to inspect.

Same BCC style as [bpf-fun](https://github.com/hed0rah/bpf-fun), as an
XDP program instead of a kprobe - this has to see raw packets before the
stack decides anything about them.

## Usage

```bash
sudo python3 xdp_ra_guard.py --iface eth0 --allow aa:bb:cc:dd:ee:ff
sudo python3 xdp_ra_guard.py --iface veth-lan --allow <router-mac> --allow <router-mac-2>
```

Every Router Advertisement decision (passed, dropped-unauthorized,
dropped-fragmented) is logged live with source MAC and address.

## Requirements

- Linux with BCC (`python3-bpfcc` / `bcc-tools`, depending on distro)
- Root

## Pairs with

`demos/10-attack-lab`'s rogue RA attack and `tools/ndp_snoop` - stand up
the attack in a netns sandbox, run this alongside it, and watch it get
dropped.
