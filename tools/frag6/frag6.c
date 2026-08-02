/*
 * frag6 - hand-craft IPv6 atomic and overlapping fragments.
 *
 * Builds and sends raw Ethernet+IPv6 frames from scratch (AF_PACKET,
 * no libpcap/scapy/libnet) to demonstrate two distinct, RFC-documented
 * IPv6 fragmentation hazards:
 *
 *   atomic  - a single packet that carries a Fragment header (Next
 *             Header 44) but is not actually fragmented (offset 0,
 *             M=0). Historically some stateless filters treat "has a
 *             fragment header" as "can't fully inspect this, let it
 *             through" even though the packet is complete and fully
 *             parseable. See RFC 6946, "Processing of IPv6 'Atomic'
 *             Fragments".
 *
 *   overlap - two fragments that both claim to cover byte range
 *             [0, frag-size): one carrying decoy bytes (M=1, "more
 *             data follows"), the other carrying the real, complete
 *             payload (M=0, "this is everything"). A spec-compliant
 *             stack must discard the whole reassembled datagram the
 *             instant it detects overlapping fragments (RFC 5722,
 *             "Handling of Overlapping IPv6 Fragments") - so running
 *             this against a compliant target should deliver nothing
 *             at all. Against a non-compliant one, which content wins
 *             (decoy or real, first-fragment-wins or last-wins) is the
 *             exact ambiguity classic IDS/firewall evasion abuses.
 *             Background: Atlasis, "Attacking IPv6 Implementation
 *             Using Fragmentation" (2012).
 *
 * Resolves the destination's link-layer address itself via a real
 * Neighbor Solicitation/Advertisement exchange (see ipv6-fun's
 * deep-dive.md, Neighbor Discovery section) unless --dst-mac is given.
 *
 * Real-interface capable - see the authorization banner in the repo
 * README. Needs CAP_NET_RAW (run as root).
 *
 * Usage:
 *   frag6 --iface eth0 --dst fd00::2 --mode atomic --payload icmp6-echo
 *   frag6 --iface eth0 --dst fd00::2 --mode overlap --frag-size 8
 *   frag6 --iface eth0 --dst fd00::2 --dst-mac aa:bb:cc:dd:ee:ff --mode atomic
 *   frag6 --iface eth0 --dst fd00::2 --mode atomic \
 *         --raw-payload deadbeefcafe0102 --next-header 17
 *
 * Build: gcc -O2 -Wall -o frag6 frag6.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <poll.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

/* ------------------------------------------------------------------ */
/* wire-format structs - fixed by RFC, packed to match the wire exactly */
/* ------------------------------------------------------------------ */

struct eth_hdr_t {
    uint8_t  h_dest[6];
    uint8_t  h_source[6];
    uint16_t h_proto;
} __attribute__((packed));

struct ip6_hdr_t {
    uint8_t  ver_tc_fl[4];
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  saddr[16];
    uint8_t  daddr[16];
} __attribute__((packed));

struct frag_hdr_t {
    uint8_t  next_header;
    uint8_t  reserved;
    uint16_t off_res_m;      /* offset(13) | reserved(2) | M(1), big-endian */
    uint32_t identification;
} __attribute__((packed));

struct icmp6_echo_t {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} __attribute__((packed));

struct ndp_ns_t {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t reserved;
    uint8_t  target[16];
    uint8_t  opt_type;       /* 1 = Source Link-Layer Address */
    uint8_t  opt_len;        /* in 8-byte units */
    uint8_t  opt_mac[6];
} __attribute__((packed));

struct ndp_na_fixed_t {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t flags;
    uint8_t  target[16];
} __attribute__((packed));

#define ETHERTYPE_IPV6   0x86DD
#define NH_HOPOPTS       0
#define NH_TCP           6
#define NH_UDP           17
#define NH_FRAGMENT      44
#define NH_ICMPV6        58
#define NH_NONE          59

/* ------------------------------------------------------------------ */
/* checksums                                                          */
/* ------------------------------------------------------------------ */

static uint16_t checksum16(const void *data, size_t len) {
    const uint8_t *p = data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += ((uint32_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += (uint32_t)p[0] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/* RFC 8200 8.1 pseudo-header: src(16) dst(16) upper-layer-len(4)
 * zero(3) next-header(1), followed by the upper-layer data itself.
 * "upper-layer length" and "next header" here are the FINAL protocol's
 * (e.g. ICMPv6's), never the Fragment header's own next-header field -
 * the checksum is computed as if the packet had never been fragmented. */
static uint16_t upper_layer_checksum(const uint8_t src[16], const uint8_t dst[16],
                                      uint8_t next_header,
                                      const uint8_t *payload, size_t payload_len) {
    uint8_t buf[2048];
    if (payload_len > sizeof(buf) - 40) {
        fprintf(stderr, "frag6: payload too large for checksum scratch buffer\n");
        exit(1);
    }
    memcpy(buf, src, 16);
    memcpy(buf + 16, dst, 16);
    uint32_t len_be = htonl((uint32_t)payload_len);
    memcpy(buf + 32, &len_be, 4);
    buf[36] = 0; buf[37] = 0; buf[38] = 0;
    buf[39] = next_header;
    memcpy(buf + 40, payload, payload_len);
    return checksum16(buf, 40 + payload_len);
}

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

static void die(const char *msg) {
    fprintf(stderr, "frag6: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void mac_to_str(const uint8_t mac[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int parse_mac(const char *s, uint8_t out[6]) {
    unsigned b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
    return 0;
}

/* returns the number of bytes decoded, or -1 on a malformed hex string */
static int parse_hex_payload(const char *hex, uint8_t *out, size_t out_cap) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t n = hlen / 2;
    if (n > out_cap) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return (int)n;
}

static void solicited_node_multicast(const uint8_t addr[16], uint8_t mcast_out[16]) {
    static const uint8_t prefix[13] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff};
    memcpy(mcast_out, prefix, 13);
    memcpy(mcast_out + 13, addr + 13, 3);
}

/* RFC 2464: the Ethernet multicast MAC for an IPv6 multicast address is
 * 33:33 followed by the address's low 32 bits. */
static void multicast_mac_for(const uint8_t mcast_addr[16], uint8_t mac_out[6]) {
    mac_out[0] = 0x33;
    mac_out[1] = 0x33;
    memcpy(mac_out + 2, mcast_addr + 12, 4);
}

/* ------------------------------------------------------------------ */
/* interface introspection                                            */
/* ------------------------------------------------------------------ */

static int get_iface_mac(int fd, const char *iface, uint8_t mac_out[6]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) return -1;
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int get_link_local_addr(const char *iface, uint8_t addr_out[16]) {
    struct ifaddrs *ifap, *p;
    int found = 0;
    if (getifaddrs(&ifap) != 0) return -1;
    for (p = ifap; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET6) continue;
        if (strcmp(p->ifa_name, iface) != 0) continue;
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)p->ifa_addr;
        uint8_t *a = sin6->sin6_addr.s6_addr;
        if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) {
            memcpy(addr_out, a, 16);
            found = 1;
            break;
        }
    }
    freeifaddrs(ifap);
    return found ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* raw socket send/receive                                            */
/* ------------------------------------------------------------------ */

static int open_raw_socket(int ifindex) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) die("socket(AF_PACKET) - are you root? (needs CAP_NET_RAW)");

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) die("bind");
    return fd;
}

static ssize_t send_frame(int fd, int ifindex, const uint8_t dst_mac[6],
                           const uint8_t *frame, size_t len) {
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = ETH_ALEN;
    sll.sll_protocol = htons(ETH_P_IPV6);
    memcpy(sll.sll_addr, dst_mac, 6);
    return sendto(fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll));
}

/* ------------------------------------------------------------------ */
/* neighbor discovery - resolve dst's MAC ourselves                   */
/* ------------------------------------------------------------------ */

static size_t build_ns_frame(uint8_t *buf, const uint8_t src_mac[6],
                              const uint8_t src_ip[16], const uint8_t target_ip[16]) {
    uint8_t mcast_ip[16], mcast_mac[6];
    solicited_node_multicast(target_ip, mcast_ip);
    multicast_mac_for(mcast_ip, mcast_mac);

    struct eth_hdr_t *eth = (struct eth_hdr_t *)buf;
    memcpy(eth->h_dest, mcast_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETHERTYPE_IPV6);

    struct ip6_hdr_t *ip6 = (struct ip6_hdr_t *)(buf + sizeof(*eth));
    ip6->ver_tc_fl[0] = 0x60; ip6->ver_tc_fl[1] = 0; ip6->ver_tc_fl[2] = 0; ip6->ver_tc_fl[3] = 0;
    ip6->next_header = NH_ICMPV6;
    ip6->hop_limit = 255; /* NDP must use hop limit 255, RFC 4861 7.1.1 */
    memcpy(ip6->saddr, src_ip, 16);
    memcpy(ip6->daddr, mcast_ip, 16);

    struct ndp_ns_t *ns = (struct ndp_ns_t *)((uint8_t *)ip6 + sizeof(*ip6));
    ns->type = 135;
    ns->code = 0;
    ns->checksum = 0;
    ns->reserved = 0;
    memcpy(ns->target, target_ip, 16);
    ns->opt_type = 1;
    ns->opt_len = 1; /* 8-byte units */
    memcpy(ns->opt_mac, src_mac, 6);

    ip6->payload_len = htons((uint16_t)sizeof(*ns));
    ns->checksum = htons(upper_layer_checksum(ip6->saddr, ip6->daddr, NH_ICMPV6,
                                               (uint8_t *)ns, sizeof(*ns)));

    return sizeof(*eth) + sizeof(*ip6) + sizeof(*ns);
}

/* Sends up to 3 Neighbor Solicitations, 1s apart, and waits for a
 * matching Neighbor Advertisement. Returns 0 and fills resolved_mac on
 * success, -1 on timeout. */
static int resolve_neighbor(int fd, int ifindex, const uint8_t src_mac[6],
                             const uint8_t src_ip[16], const uint8_t target_ip[16],
                             uint8_t resolved_mac[6]) {
    uint8_t frame[128];
    uint8_t mcast_ip[16], mcast_mac[6];
    solicited_node_multicast(target_ip, mcast_ip);
    multicast_mac_for(mcast_ip, mcast_mac);
    size_t frame_len = build_ns_frame(frame, src_mac, src_ip, target_ip);

    for (int attempt = 0; attempt < 3; attempt++) {
        if (send_frame(fd, ifindex, mcast_mac, frame, frame_len) < 0) die("sendto (NS)");

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        struct timespec start;
        clock_gettime(CLOCK_MONOTONIC, &start);

        for (;;) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
                               (now.tv_nsec - start.tv_nsec) / 1000000L;
            long remaining_ms = 1000L - elapsed_ms;
            if (remaining_ms <= 0) break; /* this attempt's timeout expired */

            int rc = poll(&pfd, 1, (int)remaining_ms);
            if (rc < 0) die("poll");
            if (rc == 0) break; /* this attempt's timeout expired */

            uint8_t rbuf[2048];
            ssize_t n = recv(fd, rbuf, sizeof(rbuf), 0);
            if (n < (ssize_t)(sizeof(struct eth_hdr_t) + sizeof(struct ip6_hdr_t) +
                               sizeof(struct ndp_na_fixed_t)))
                continue;

            struct eth_hdr_t *eth = (struct eth_hdr_t *)rbuf;
            if (eth->h_proto != htons(ETHERTYPE_IPV6)) continue;

            struct ip6_hdr_t *ip6 = (struct ip6_hdr_t *)(rbuf + sizeof(*eth));
            if (ip6->next_header != NH_ICMPV6) continue;

            struct ndp_na_fixed_t *na = (struct ndp_na_fixed_t *)((uint8_t *)ip6 + sizeof(*ip6));
            if (na->type != 136) continue;
            if (memcmp(na->target, target_ip, 16) != 0) continue;

            memcpy(resolved_mac, eth->h_source, 6);
            return 0;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* fragment construction                                              */
/* ------------------------------------------------------------------ */

static size_t build_fragment_frame(uint8_t *buf,
                                    const uint8_t src_mac[6], const uint8_t dst_mac[6],
                                    const uint8_t src_ip[16], const uint8_t dst_ip[16],
                                    uint8_t next_header_final, uint16_t offset_units,
                                    int more_flag, uint32_t identification, uint8_t hop_limit,
                                    const uint8_t *chunk, uint16_t chunk_len) {
    struct eth_hdr_t *eth = (struct eth_hdr_t *)buf;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETHERTYPE_IPV6);

    struct ip6_hdr_t *ip6 = (struct ip6_hdr_t *)(buf + sizeof(*eth));
    ip6->ver_tc_fl[0] = 0x60; ip6->ver_tc_fl[1] = 0; ip6->ver_tc_fl[2] = 0; ip6->ver_tc_fl[3] = 0;
    ip6->payload_len = htons((uint16_t)(sizeof(struct frag_hdr_t) + chunk_len));
    ip6->next_header = NH_FRAGMENT;
    ip6->hop_limit = hop_limit;
    memcpy(ip6->saddr, src_ip, 16);
    memcpy(ip6->daddr, dst_ip, 16);

    struct frag_hdr_t *frag = (struct frag_hdr_t *)((uint8_t *)ip6 + sizeof(*ip6));
    frag->next_header = next_header_final;
    frag->reserved = 0;
    uint16_t off_res_m = (uint16_t)((offset_units << 3) | (more_flag ? 1 : 0));
    frag->off_res_m = htons(off_res_m);
    frag->identification = htonl(identification);

    uint8_t *payload_ptr = (uint8_t *)frag + sizeof(*frag);
    memcpy(payload_ptr, chunk, chunk_len);

    return sizeof(*eth) + sizeof(*ip6) + sizeof(*frag) + chunk_len;
}

/* ------------------------------------------------------------------ */
/* payload builders                                                   */
/* ------------------------------------------------------------------ */

/* 8-byte ICMPv6 echo header + 24 bytes of a counting pattern - 32
 * bytes total, matching the worked example in this repo's index.html. */
static size_t build_icmp6_echo(uint8_t *out, const uint8_t src[16], const uint8_t dst[16]) {
    struct icmp6_echo_t *echo = (struct icmp6_echo_t *)out;
    echo->type = 128;
    echo->code = 0;
    echo->checksum = 0;
    echo->identifier = htons((uint16_t)(getpid() & 0xFFFF));
    echo->sequence = htons(1);
    uint8_t *data = out + sizeof(*echo);
    for (int i = 0; i < 24; i++) data[i] = (uint8_t)i;
    size_t total = sizeof(*echo) + 24;
    echo->checksum = htons(upper_layer_checksum(src, dst, NH_ICMPV6, out, total));
    return total;
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s --iface IFACE --dst ADDR --mode atomic|overlap [options]\n\n"
        "  --iface IFACE        interface to send on (required)\n"
        "  --dst ADDR           destination IPv6 address (required)\n"
        "  --src ADDR           source address (default: iface's link-local)\n"
        "  --dst-mac MAC        skip Neighbor Discovery, use this MAC\n"
        "  --mode MODE          atomic | overlap (required)\n"
        "  --frag-size N        overlap mode: decoy fragment size in bytes, multiple of 8 (default 8)\n"
        "  --payload NAME       icmp6-echo (default)\n"
        "  --raw-payload HEX    arbitrary hex payload instead of icmp6-echo\n"
        "  --next-header N      upper-layer protocol number for --raw-payload (default 59, No Next Header)\n"
        "  --hop-limit N        default 64\n"
        "  --id N               fragment identification value (default: derived from time+pid)\n"
        "  -h, --help           this text\n\n"
        "atomic:  one packet, Fragment header present, offset 0, M=0 (RFC 6946)\n"
        "overlap: two packets both claiming offset 0 - a decoy (M=1) and the real\n"
        "         payload (M=0). A compliant stack discards both (RFC 5722).\n",
        prog);
}

int main(int argc, char **argv) {
    const char *iface = NULL, *dst_str = NULL, *src_str = NULL, *dst_mac_str = NULL;
    const char *mode = NULL, *raw_hex = NULL;
    const char *payload_name = "icmp6-echo";
    int frag_size = 8;
    int next_header_opt = NH_NONE;
    int hop_limit = 64;
    long id_opt = -1;

    static struct option longopts[] = {
        {"iface",       required_argument, 0, 'i'},
        {"dst",         required_argument, 0, 'd'},
        {"src",         required_argument, 0, 's'},
        {"dst-mac",     required_argument, 0, 'M'},
        {"mode",        required_argument, 0, 'm'},
        {"frag-size",   required_argument, 0, 'f'},
        {"payload",     required_argument, 0, 'p'},
        {"raw-payload", required_argument, 0, 'r'},
        {"next-header", required_argument, 0, 'n'},
        {"hop-limit",   required_argument, 0, 'l'},
        {"id",          required_argument, 0, 'I'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
            case 'i': iface = optarg; break;
            case 'd': dst_str = optarg; break;
            case 's': src_str = optarg; break;
            case 'M': dst_mac_str = optarg; break;
            case 'm': mode = optarg; break;
            case 'f': frag_size = atoi(optarg); break;
            case 'p': payload_name = optarg; break;
            case 'r': raw_hex = optarg; break;
            case 'n': next_header_opt = atoi(optarg); break;
            case 'l': hop_limit = atoi(optarg); break;
            case 'I': id_opt = atol(optarg); break;
            case 'h': usage(argv[0]); return 0;
            default: usage(argv[0]); return 1;
        }
    }

    if (!iface || !dst_str || !mode) {
        fprintf(stderr, "frag6: --iface, --dst, and --mode are required\n\n");
        usage(argv[0]);
        return 1;
    }
    if (strcmp(mode, "atomic") != 0 && strcmp(mode, "overlap") != 0) {
        fprintf(stderr, "frag6: --mode must be 'atomic' or 'overlap'\n");
        return 1;
    }
    if (frag_size <= 0 || frag_size % 8 != 0) {
        fprintf(stderr, "frag6: --frag-size must be a positive multiple of 8\n");
        return 1;
    }

    uint8_t dst_ip[16];
    if (inet_pton(AF_INET6, dst_str, dst_ip) != 1) {
        fprintf(stderr, "frag6: not a valid IPv6 address: %s\n", dst_str);
        return 1;
    }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) die("if_nametoindex");

    int fd = open_raw_socket(ifindex);

    uint8_t src_mac[6];
    if (get_iface_mac(fd, iface, src_mac) < 0) die("get_iface_mac");

    uint8_t src_ip[16];
    if (src_str) {
        if (inet_pton(AF_INET6, src_str, src_ip) != 1) {
            fprintf(stderr, "frag6: not a valid IPv6 address: %s\n", src_str);
            return 1;
        }
    } else if (get_link_local_addr(iface, src_ip) < 0) {
        fprintf(stderr, "frag6: couldn't find a link-local address on %s (pass --src)\n", iface);
        return 1;
    }

    uint8_t dst_mac[6];
    if (dst_mac_str) {
        if (parse_mac(dst_mac_str, dst_mac) < 0) {
            fprintf(stderr, "frag6: not a valid MAC address: %s\n", dst_mac_str);
            return 1;
        }
    } else {
        printf("resolving %s via Neighbor Discovery on %s...\n", dst_str, iface);
        if (resolve_neighbor(fd, ifindex, src_mac, src_ip, dst_ip, dst_mac) < 0) {
            fprintf(stderr,
                "frag6: no Neighbor Advertisement for %s (dead host, wrong iface, "
                "or firewalled) - pass --dst-mac to skip resolution\n", dst_str);
            close(fd);
            return 1;
        }
    }

    char src_mac_s[18], dst_mac_s[18], src_ip_s[INET6_ADDRSTRLEN], dst_ip_s[INET6_ADDRSTRLEN];
    mac_to_str(src_mac, src_mac_s);
    mac_to_str(dst_mac, dst_mac_s);
    inet_ntop(AF_INET6, src_ip, src_ip_s, sizeof(src_ip_s));
    inet_ntop(AF_INET6, dst_ip, dst_ip_s, sizeof(dst_ip_s));

    printf("src: %s (%s)\ndst: %s (%s)\nmode: %s\n\n", src_ip_s, src_mac_s, dst_ip_s, dst_mac_s, mode);

    uint8_t payload[1400];
    size_t payload_len;
    uint8_t next_header_final;

    if (raw_hex) {
        int n = parse_hex_payload(raw_hex, payload, sizeof(payload));
        if (n < 0) {
            fprintf(stderr, "frag6: --raw-payload must be an even-length hex string\n");
            return 1;
        }
        payload_len = (size_t)n;
        next_header_final = (uint8_t)next_header_opt;
        printf("payload: %zu raw bytes, next-header=%d (no checksum computed - not this tool's job for arbitrary payloads)\n\n",
               payload_len, next_header_opt);
    } else if (strcmp(payload_name, "icmp6-echo") == 0) {
        payload_len = build_icmp6_echo(payload, src_ip, dst_ip);
        next_header_final = NH_ICMPV6;
        printf("payload: %zu-byte ICMPv6 echo request, checksum computed over the complete message\n\n",
               payload_len);
    } else {
        fprintf(stderr, "frag6: unknown --payload '%s' (known: icmp6-echo)\n", payload_name);
        return 1;
    }

    uint32_t identification = (id_opt >= 0)
        ? (uint32_t)id_opt
        : (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16);

    uint8_t frame[1500];

    if (strcmp(mode, "atomic") == 0) {
        size_t len = build_fragment_frame(frame, src_mac, dst_mac, src_ip, dst_ip,
                                           next_header_final, 0, 0, identification,
                                           (uint8_t)hop_limit, payload, (uint16_t)payload_len);
        printf("atomic fragment: offset=0 M=0 id=%u payload=%zu bytes\n", identification, payload_len);
        if (send_frame(fd, ifindex, dst_mac, frame, len) < 0) die("sendto");
        printf("sent %zu bytes.\n", len);
    } else {
        uint16_t decoy_len = (uint16_t)(frag_size < (int)payload_len ? frag_size : payload_len);
        uint8_t decoy[1400];
        memset(decoy, 0x41, decoy_len); /* 'A' filler - clearly not the real content */

        size_t len1 = build_fragment_frame(frame, src_mac, dst_mac, src_ip, dst_ip,
                                            next_header_final, 0, /*more=*/1, identification,
                                            (uint8_t)hop_limit, decoy, decoy_len);
        printf("fragment 1 (decoy):  offset=0 M=1 id=%u payload=%u bytes (filler)\n",
               identification, decoy_len);
        if (send_frame(fd, ifindex, dst_mac, frame, len1) < 0) die("sendto (fragment 1)");

        size_t len2 = build_fragment_frame(frame, src_mac, dst_mac, src_ip, dst_ip,
                                            next_header_final, 0, /*more=*/0, identification,
                                            (uint8_t)hop_limit, payload, (uint16_t)payload_len);
        printf("fragment 2 (real):   offset=0 M=0 id=%u payload=%zu bytes\n",
               identification, payload_len);
        if (send_frame(fd, ifindex, dst_mac, frame, len2) < 0) die("sendto (fragment 2)");

        printf("\nsent %zu + %zu bytes. both fragments claim offset 0 - a stack that\n"
               "follows RFC 5722 discards the entire reassembled datagram; anything\n"
               "else it delivers (decoy, real, or a splice of both) is a bug worth knowing about.\n",
               len1, len2);
    }

    close(fd);
    return 0;
}
