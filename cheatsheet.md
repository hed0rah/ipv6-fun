# IPv6 Cheatsheet

Quick reference. See [deep-dive.md](deep-dive.md) for the full walkthrough,
history, and citations - every RFC below is linked in
[deep-dive.md#references](deep-dive.md#references).

## Address types & scopes

Defined in [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291).

| Prefix          | Name                    | Scope        | Notes                                             |
|-----------------|-------------------------|--------------|----------------------------------------------------|
| `fe80::/10`     | link-local unicast      | link         | auto-assigned on every interface, never routed     |
| `fc00::/7`      | unique local (ULA)      | site/private | `fd00::/8` is the "randomly generated" half in use |
| `2000::/3`      | global unicast (GUA)    | global       | the routable, internet-facing space                |
| `ff00::/8`      | multicast               | varies       | scope encoded in the address itself, see below     |
| `ff02::1`       | all-nodes multicast     | link         | every IPv6 node listens here                       |
| `ff02::2`       | all-routers multicast   | link         | every IPv6 router listens here                     |
| `ff02::1:ffXX:XXXX` | solicited-node multicast | link    | last 24 bits of the unicast address, used by NDP   |
| `::1`           | loopback                | host         | the `127.0.0.1` of IPv6                            |
| `::`            | unspecified              | -            | "no address yet" - used during DAD                 |

Multicast scope is the second hex digit after `ff`: `ff02` = link-local,
`ff05` = site-local, `ff0e` = global. `ffX2::1` is always "all nodes" at
scope X.

## Core commands

```bash
ip -6 addr show                      # list addresses, flags (tentative, deprecated, mngtmpaddr)
ip -6 route show                     # routing table
ip -6 neigh show                     # neighbor (NDP) cache - the ARP table equivalent
ip -6 addr add fd00::1/64 dev eth0   # assign a static address
sysctl net.ipv6.conf.all.disable_ipv6

ping6 ff02::1%eth0                   # ping all nodes on the local link
ping -6 2001:4860:4860::8888         # ping6 folded into ping on modern iproute2

# ndisc6 suite (apt install ndisc6)
rdisc6 eth0                          # send RS, show RA response
ndisc6 fe80::1 eth0                  # send NS, show NA response
tcpdump6 -i eth0                     # tcpdump -i eth0 ip6
```

## ICMPv6 type quick reference

Defined in [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443); NDP types
133-137 in [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861).

| Type | Name                        | Role                          |
|------|-----------------------------|--------------------------------|
| 1    | Destination Unreachable     | error                          |
| 2    | Packet Too Big              | error, drives PMTUD            |
| 3    | Time Exceeded               | error (hop limit / reassembly) |
| 4    | Parameter Problem           | error                          |
| 128  | Echo Request                | ping                           |
| 129  | Echo Reply                  | ping                           |
| 130  | Multicast Listener Query    | MLD                            |
| 133  | Router Solicitation (RS)    | NDP                            |
| 134  | Router Advertisement (RA)   | NDP                            |
| 135  | Neighbor Solicitation (NS)  | NDP - ARP replacement          |
| 136  | Neighbor Advertisement (NA) | NDP - ARP replacement          |
| 137  | Redirect                    | NDP                            |

IPv6 has no ARP, no broadcast, and no separate ping protocol - ICMPv6
carries all of it. A firewall that blocks ICMPv6 wholesale breaks NDP and
therefore breaks IPv6 itself.

## Extension header order

Order mandated by [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200) §4.1.

When present, extension headers must appear in this order between the
fixed IPv6 header and the upper-layer payload:

```
IPv6 header
 -> Hop-by-Hop Options       (0)
 -> Destination Options      (60, for intermediate routing headers)
 -> Routing                  (43)
 -> Fragment                 (44)
 -> Authentication (AH)      (51)
 -> Encapsulating Security   (50)
 -> Destination Options      (60, for the final destination)
 -> Upper-layer (TCP/UDP/ICMPv6)
```

Out-of-order or repeated extension headers are a classic firewall/IDS
evasion technique - see `tools/frag6` and `demos/06-extension-headers.py`.

## SLAAC vs DHCPv6

SLAAC: [RFC 4862](https://www.rfc-editor.org/rfc/rfc4862). DHCPv6:
[RFC 8415](https://www.rfc-editor.org/rfc/rfc8415).

| | SLAAC | DHCPv6 stateful | DHCPv6 stateless |
|---|---|---|---|
| Address source | RA prefix + EUI-64/privacy | DHCPv6 server | RA (address) |
| Other config (DNS, etc) | RDNSS option or none | DHCPv6 server | DHCPv6 server |
| Needs a server | no | yes | yes |
| M/O flags in RA | M=0 O=0/1 | M=1 | M=0 O=1 |

## History (short version)

IPv6 traces to a 1993 IETF call for proposals
([RFC 1550](https://www.rfc-editor.org/rfc/rfc1550)), picked SIPP over
TUBA/PIP/CATNIP in 1995
([RFC 1752](https://www.rfc-editor.org/rfc/rfc1752)), and didn't reach
full Internet Standard until [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200)
in 2017 - 22 years after the first spec. Full timeline, the RH0
amplification attack, and the "why is there no IPv5" trivia:
[deep-dive.md#a-brief-history-of-ipv6](deep-dive.md#a-brief-history-of-ipv6).
