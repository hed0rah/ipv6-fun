#!/usr/bin/env python3
"""ndp_snoop -- watch Neighbor Discovery Protocol traffic live via XDP.

Decodes Router Solicitation / Router Advertisement / Neighbor Solicitation /
Neighbor Advertisement / Redirect (ICMPv6 types 133-137) crossing an
interface -- the same messages covered in ipv6-fun's deep-dive.md under
Neighbor Discovery and Router Advertisements. Read-only: the XDP program
always returns XDP_PASS, it never drops or delays a packet.

Written in the same BCC style as bpf-fun's kprobe tools (tcp_connect.py,
dns_snoop.py) -- see https://github.com/hed0rah/bpf-fun -- but hooks XDP
instead of a kprobe, since NDP is packet-shaped, not syscall-shaped.

Limitation: parses only ICMPv6 that follows the fixed IPv6 header
directly -- NDP messages hidden behind extension headers won't be seen.
See xdp_ra_guard.py in this repo for a tool that walks the header chain.

Usage:
    sudo python3 ndp_snoop.py --iface eth0
"""

import argparse
import socket
import time
from bcc import BPF

parser = argparse.ArgumentParser(description="Snoop IPv6 Neighbor Discovery traffic via XDP")
parser.add_argument("--iface", required=True, help="interface to watch")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/bpf.h>

struct ndp_eth_t {
    u8  h_dest[6];
    u8  h_source[6];
    u16 h_proto;
} __attribute__((packed));

struct ndp_ip6_t {
    u8  ver_tc_fl[4];
    u16 payload_len;
    u8  nexthdr;
    u8  hoplimit;
    u8  saddr[16];
    u8  daddr[16];
} __attribute__((packed));

struct ndp_icmp6_t {
    u8  type;
    u8  code;
    u16 checksum;
} __attribute__((packed));

struct ndp_event_t {
    u8 icmp6_type;
    u8 src_mac[6];
    u8 saddr[16];
    u8 daddr[16];
    u8 target[16];   // only populated for NS (135) / NA (136)
};

BPF_PERF_OUTPUT(events);

int xdp_ndp_snoop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ndp_eth_t *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(0x86DD)) return XDP_PASS;

    struct ndp_ip6_t *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
    if (ip6->nexthdr != 58) return XDP_PASS; // ICMPv6 only, see docstring limitation

    struct ndp_icmp6_t *icmp6 = (void *)(ip6 + 1);
    if ((void *)(icmp6 + 1) > data_end) return XDP_PASS;
    if (icmp6->type < 133 || icmp6->type > 137) return XDP_PASS;

    struct ndp_event_t evt = {};
    evt.icmp6_type = icmp6->type;
    __builtin_memcpy(evt.src_mac, eth->h_source, 6);
    __builtin_memcpy(evt.saddr, ip6->saddr, 16);
    __builtin_memcpy(evt.daddr, ip6->daddr, 16);

    if (icmp6->type == 135 || icmp6->type == 136) {
        void *target = (void *)icmp6 + 8; // reserved/flags(4) + skip to target
        if (target + 16 <= data_end) {
            __builtin_memcpy(evt.target, target, 16);
        }
    }

    events.perf_submit(ctx, &evt, sizeof(evt));
    return XDP_PASS;
}
"""

b = BPF(text=bpf_text)
fn = b.load_func("xdp_ndp_snoop", BPF.XDP)
b.attach_xdp(args.iface, fn, 0)

ICMP6_NAMES = {133: "RS", 134: "RA", 135: "NS", 136: "NA", 137: "Redirect"}
counts = {}

print(f"Snooping NDP traffic on {args.iface}... Ctrl-C to stop\n")
print(f"{'TIME':<10} {'TYPE':<10} {'SRC MAC':<18} {'SOURCE':<28} {'DEST':<24} {'TARGET'}")
print("-" * 110)


def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    ts = time.strftime("%H:%M:%S")
    kind = ICMP6_NAMES.get(evt.icmp6_type, str(evt.icmp6_type))
    counts[kind] = counts.get(kind, 0) + 1
    src_mac = ":".join(f"{x:02x}" for x in bytes(evt.src_mac))
    saddr = socket.inet_ntop(socket.AF_INET6, bytes(evt.saddr))
    daddr = socket.inet_ntop(socket.AF_INET6, bytes(evt.daddr))
    target = ""
    if evt.icmp6_type in (135, 136):
        target = socket.inet_ntop(socket.AF_INET6, bytes(evt.target))
    print(f"{ts:<10} {kind:<10} {src_mac:<18} {saddr:<28} {daddr:<24} {target}")


b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nSummary:")
    if counts:
        for k in sorted(counts):
            print(f"  {k}: {counts[k]}")
    else:
        print("  no NDP traffic seen.")
finally:
    b.remove_xdp(args.iface, 0)
    print("XDP program detached. Done.")
