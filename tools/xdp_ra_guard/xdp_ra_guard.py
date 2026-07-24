#!/usr/bin/env python3
"""xdp_ra_guard -- drop unauthorized Router Advertisements at the XDP layer.

A real RA Guard, not a naive one. Two things most simple implementations
skip, per RFC 7113's "RA-Guard Evasion" and RFC 6980's "Security
Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery":

  1. It walks the IPv6 extension header chain (Hop-by-Hop, Routing,
     Destination Options) looking for ICMPv6, instead of only checking
     whether the fixed header's Next Header is 58. A guard that only
     checks the fixed header is exactly what RFC 7113 describes being
     evaded by burying the RA behind an extension header.
  2. It drops fragmented traffic headed for a multicast or link-local
     destination outright, rather than attempting reassembly. Per
     RFC 6980, legitimate Neighbor Discovery messages are always small
     enough to never need fragmentation -- a fragmented ND-shaped packet
     is itself the attack, not something worth reassembling to inspect.

Router Advertisements from a MAC not in --allow are dropped; everything
else passes through untouched. See ipv6-fun's deep-dive.md, Firewalling
section, for the background these two RFCs are cited from.

Written in the same BCC style as bpf-fun's tools -- see
https://github.com/hed0rah/bpf-fun -- as an XDP program instead of a
kprobe, since this has to see raw packets before the stack decides
anything about them.

Usage:
    sudo python3 xdp_ra_guard.py --iface eth0 --allow aa:bb:cc:dd:ee:ff
    sudo python3 xdp_ra_guard.py --iface veth-lan --allow <router-mac> --allow <router-mac-2>
"""

import argparse
import ctypes
import socket
import time
from bcc import BPF

parser = argparse.ArgumentParser(description="XDP-based IPv6 Router Advertisement Guard")
parser.add_argument("--iface", required=True, help="interface to protect")
parser.add_argument("--allow", action="append", required=True, metavar="MAC",
                    help="MAC address of a legitimate router (repeatable)")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/bpf.h>

#define RAG_HOPOPTS  0
#define RAG_ROUTING  43
#define RAG_FRAGMENT 44
#define RAG_DSTOPTS  60
#define RAG_ICMPV6   58

struct rag_eth_t {
    u8  h_dest[6];
    u8  h_source[6];
    u16 h_proto;
} __attribute__((packed));

struct rag_ip6_t {
    u8  ver_tc_fl[4];
    u16 payload_len;
    u8  nexthdr;
    u8  hoplimit;
    u8  saddr[16];
    u8  daddr[16];
} __attribute__((packed));

struct rag_ext_hdr_t {
    u8 next_header;
    u8 hdr_ext_len;
} __attribute__((packed));

struct rag_icmp6_t {
    u8  type;
    u8  code;
    u16 checksum;
} __attribute__((packed));

struct rag_event_t {
    u8 action;     // 0=passed-allowed-RA, 1=dropped-unauthorized-RA, 2=dropped-fragmented-suspect
    u8 src_mac[6];
    u8 saddr[16];
};

BPF_HASH(allowed_macs, u64, u8, 64);
BPF_PERF_OUTPUT(events);

static inline u64 rag_mac_key(u8 *mac) {
    u64 k = 0;
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        k = (k << 8) | mac[i];
    }
    return k;
}

int xdp_ra_guard(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct rag_eth_t *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(0x86DD)) return XDP_PASS;

    struct rag_ip6_t *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end) return XDP_PASS;

    void *cursor = (void *)(ip6 + 1);
    u8 nexthdr = ip6->nexthdr;
    u8 saw_fragment = 0;
    u8 is_icmpv6 = 0;

    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (nexthdr == RAG_ICMPV6) { is_icmpv6 = 1; break; }
        if (nexthdr == RAG_FRAGMENT) { saw_fragment = 1; break; }
        if (nexthdr != RAG_HOPOPTS && nexthdr != RAG_ROUTING && nexthdr != RAG_DSTOPTS) {
            break; // some other upper-layer protocol; not our concern
        }
        struct rag_ext_hdr_t *eh = cursor;
        if ((void *)(eh + 1) > data_end) return XDP_PASS;
        nexthdr = eh->next_header;
        cursor += (eh->hdr_ext_len + 1) * 8;
        if (cursor > data_end) return XDP_PASS;
    }

    if (saw_fragment) {
        // multicast (ff00::/8) or link-local (fe80::/10) destination: the
        // scopes any legitimate RA/NS/NA ever targets. RFC 6980: drop
        // fragmented ND-shaped traffic rather than reassemble it.
        u8 d0 = ip6->daddr[0], d1 = ip6->daddr[1];
        if (d0 == 0xff || (d0 == 0xfe && (d1 & 0xc0) == 0x80)) {
            struct rag_event_t evt = {};
            evt.action = 2;
            __builtin_memcpy(evt.src_mac, eth->h_source, 6);
            __builtin_memcpy(evt.saddr, ip6->saddr, 16);
            events.perf_submit(ctx, &evt, sizeof(evt));
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    if (!is_icmpv6) return XDP_PASS;

    struct rag_icmp6_t *icmp6 = cursor;
    if ((void *)(icmp6 + 1) > data_end) return XDP_PASS;
    if (icmp6->type != 134) return XDP_PASS; // only Router Advertisement is our concern

    u64 key = rag_mac_key(eth->h_source);
    u8 *allowed = allowed_macs.lookup(&key);

    struct rag_event_t evt = {};
    __builtin_memcpy(evt.src_mac, eth->h_source, 6);
    __builtin_memcpy(evt.saddr, ip6->saddr, 16);

    if (allowed) {
        evt.action = 0;
        events.perf_submit(ctx, &evt, sizeof(evt));
        return XDP_PASS;
    }

    evt.action = 1;
    events.perf_submit(ctx, &evt, sizeof(evt));
    return XDP_DROP;
}
"""


def mac_to_key(mac_str):
    raw = bytes.fromhex(mac_str.replace(":", "").replace("-", ""))
    if len(raw) != 6:
        raise ValueError(f"not a MAC address: {mac_str}")
    return int.from_bytes(raw, "big")


def mac_to_str(raw6):
    return ":".join(f"{b:02x}" for b in raw6)


b = BPF(text=bpf_text)
fn = b.load_func("xdp_ra_guard", BPF.XDP)
b.attach_xdp(args.iface, fn, 0)

allowed_macs = b["allowed_macs"]
for mac in args.allow:
    key = ctypes.c_ulonglong(mac_to_key(mac))
    allowed_macs[key] = ctypes.c_uint8(1)

ACTIONS = {
    0: "PASS  (allowed router)",
    1: "DROP  (unauthorized RA)",
    2: "DROP  (fragmented, RFC 6980)",
}
counts = {0: 0, 1: 0, 2: 0}

print(f"RA Guard active on {args.iface}, allowing RAs from: {', '.join(args.allow)}")
print("Ctrl-C to stop\n")
print(f"{'TIME':<10} {'ACTION':<28} {'SRC MAC':<18} {'SRC ADDR'}")
print("-" * 84)


def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    ts = time.strftime("%H:%M:%S")
    src_mac = mac_to_str(bytes(evt.src_mac))
    src_addr = socket.inet_ntop(socket.AF_INET6, bytes(evt.saddr))
    counts[evt.action] = counts.get(evt.action, 0) + 1
    print(f"{ts:<10} {ACTIONS.get(evt.action, '?'):<28} {src_mac:<18} {src_addr}")


b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nSummary:")
    print(f"  allowed RAs passed:      {counts[0]}")
    print(f"  unauthorized RAs dropped: {counts[1]}")
    print(f"  fragmented drops:         {counts[2]}")
finally:
    b.remove_xdp(args.iface, 0)
    print("XDP program detached. Done.")
