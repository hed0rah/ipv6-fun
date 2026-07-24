# ndp_snoop

Watches Neighbor Discovery Protocol traffic live via an XDP hook: RS, RA,
NS, NA, and Redirect (ICMPv6 types 133-137), decoded and printed as they
cross an interface. Read-only - the XDP program always returns
`XDP_PASS`, it never drops or delays a packet.

Same BCC style as [bpf-fun](https://github.com/hed0rah/bpf-fun)'s kprobe
tools (`tcp_connect.py`, `dns_snoop.py`), but hooked at XDP instead of a
kprobe, since NDP is packet-shaped, not syscall-shaped.

## Usage

```bash
sudo python3 ndp_snoop.py --iface eth0
```

## Requirements

- Linux with BCC (`python3-bpfcc` / `bcc-tools`, depending on distro)
- Root

## Limitation

Parses only ICMPv6 that follows the fixed IPv6 header directly - an NDP
message hidden behind an extension header won't be seen. See
[`tools/xdp_ra_guard`](../xdp_ra_guard) for a tool that walks the full
header chain, which is what a real defense against that evasion needs.
