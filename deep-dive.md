# IPv6 Deep Dive

See [demos/](demos/) for the runnable side of each section,
[cheatsheet.md](cheatsheet.md) for the compressed quick-reference version
of the tables below, and [References](#references) at the bottom for
every RFC and source cited inline.

## Index

- [A Brief History of IPv6](#a-brief-history-of-ipv6)
1. [Address Anatomy](#address-anatomy)
2. [SLAAC](#slaac)
3. [Neighbor Discovery](#neighbor-discovery)
4. [Router Advertisements](#router-advertisements)
5. [ICMPv6](#icmpv6)
6. [Extension Headers](#extension-headers)
7. [Multicast](#multicast)
8. [DHCPv6](#dhcpv6)
9. [Transition Mechanisms](#transition-mechanisms)
10. [Attack Lab](#attack-lab)
11. [Firewalling](#firewalling)
12. [Capstone: Build a v6 Segment](#capstone)
- [References](#references)

---

## A Brief History of IPv6

IPv4's 32-bit address space (~4.3 billion addresses) was already a
known long-term problem by the early 1990s - the internet was growing
faster than anyone in the 1970s had sized the address field for. In
December 1993 the IETF formally opened the search for a successor with
[RFC 1550](https://www.rfc-editor.org/rfc/rfc1550), "IP: Next Generation
(IPng) White Paper Solicitation."

Four competing proposals were submitted: **TUBA** (TCP/UDP over
CLNP, reusing ISO's OSI-era network layer,
[RFC 1347](https://www.rfc-editor.org/rfc/rfc1347)), **SIPP** (Simple
Internet Protocol Plus, [RFC 1710](https://www.rfc-editor.org/rfc/rfc1710)),
**CATNIP** (Common Architecture for the Internet,
[RFC 1707](https://www.rfc-editor.org/rfc/rfc1707)), and **PIP** (the
P Internet Protocol). In January 1995 the IPng Area Directors published
[RFC 1752](https://www.rfc-editor.org/rfc/rfc1752), "The Recommendation
for the IP Next Generation Protocol," picking SIPP as the base - but
widening its address field from 64 bits to 128 - and naming the result
IPv6.

**Fun fact:** there was never an IPv4-compatible "IPv5" you skipped
past. Version number 5 in the shared IP header's 4-bit version field had
already been claimed by the experimental Internet Stream Protocol
(ST-II, [RFC 1190](https://www.rfc-editor.org/rfc/rfc1190), later
ST2+ in [RFC 1819](https://www.rfc-editor.org/rfc/rfc1819)), an early
real-time streaming protocol that never saw wide deployment. IPv6 is
called v6 because 5 was already spoken for, not because five prior
versions of IP shipped.

[RFC 1883](https://www.rfc-editor.org/rfc/rfc1883) (December 1995),
authored by Steve Deering and Bob Hinden, was the first formal IPv6
spec. From 1996 to 2006 the **6bone** - a global experimental IPv6
network tunneled over the existing IPv4 internet - let early
implementers actually run the protocol before real address allocation
existed; its planned sunset date of June 6, 2006 was fixed years ahead
of time in [RFC 3701](https://www.rfc-editor.org/rfc/rfc3701).
[RFC 2460](https://www.rfc-editor.org/rfc/rfc2460) (December 1998)
obsoleted RFC 1883 and became the spec everyone actually implemented
against for the next 19 years.

2007 produced one of IPv6's few "a core feature got killed for being a
live security hole" moments: researchers Philippe Biondi and Arnaud
Ebalard publicly demonstrated that the Routing Header Type 0 feature
(arbitrary source routing, see [Extension Headers](#extension-headers))
could be abused to bounce traffic repeatedly between two colluding
routers, amplifying bandwidth the same way IPv4 source-routing abuse
once did. [RFC 5095](https://www.rfc-editor.org/rfc/rfc5095) deprecated
RH0 within the year.

IPv4 exhaustion, meanwhile, stopped being theoretical: IANA handed out
the last five unallocated /8 blocks to the five RIRs on February 3, 2011
- the formal moment the global free pool hit zero, even though
individual RIRs kept issuing from their own remaining stock afterward
(APNIC exhausted its regular pool that same April; ARIN didn't run dry
until September 2015). On June 8, 2011, Google, Facebook, Yahoo, and
other major sites enabled IPv6 simultaneously for 24 hours as a
coordinated real-world test - **World IPv6 Day**. A year later, on
June 6, 2012, the same participants plus home router and ISP vendors
turned it on permanently instead of just for a day - **World IPv6
Launch**.

[RFC 8200](https://www.rfc-editor.org/rfc/rfc8200) (July 2017) finally
obsoleted RFC 2460 and elevated IPv6 to full Internet Standard (STD 86)
- 22 years after the first spec shipped. It's the version cited
throughout this document.

## Address Anatomy

128 bits, written as 8 groups of 4 hex digits, leading zeros in a group
droppable, and at most one run of `::` per address (if two runs were
allowed, expansion would be ambiguous - the parser can't tell how many
zero groups belong to each side). `2001:0db8:0000:0000:0000:0000:0000:0001`
compresses to `2001:db8::1`. The address format and allocation rules
(including `fc00::/7`, `fe80::/10`, and the reserved `2001:db8::/32`
documentation prefix used throughout this repo) are defined in
[RFC 4291](https://www.rfc-editor.org/rfc/rfc4291).

Under SLAAC a global unicast address splits exactly in half:

```
| 64 bits: routed prefix          | 64 bits: interface identifier   |
| 2001:0db8:0000:0001             | 021a:2bff:fe3c:4d5e             |
```

The interface identifier isn't random by default - it's derived from the
MAC address via **EUI-64** ([RFC 4291](https://www.rfc-editor.org/rfc/rfc4291)
appendix A, building on the IEEE's own 64-bit extended unique identifier
format):

```
MAC address:      00:1a:2b : 3c:4d:5e
                   OUI(24)    NIC(24)

split + insert 0xfffe in the middle:
                   00:1a:2b:ff:fe:3c:4d:5e

flip the universal/local bit (bit 0x02 of the first octet):
                   00 XOR 02 = 02
                   -----------------------------------
                   02:1a:2b:ff:fe:3c:4d:5e

interface ID:      021a:2bff:fe3c:4d5e
```

That bit flip is backwards from what most people guess: `0` in that bit
position means "globally unique" (burned-in MAC), `1` means "locally
administered." EUI-64 sets the bit to say "this was built from a
universally-unique MAC," which inverts the raw MAC's own bit convention.
It's also why every SLAAC address on a given NIC has the same interface
ID forever - which is exactly the tracking problem RFC 4941 privacy
extensions exist to solve (see [SLAAC](#slaac)).

**Multicast** (`ff00::/8`) encodes its own scope in the address, no
routing table lookup needed to know how far a packet can travel:

```
|   8 bits  | 4 bits | 4 bits |          112 bits           |
| 1111 1111 |  flgs  |  scop  |          group ID            |
```

`flgs` is `0RPT`: `T`=0 means a well-known IANA-assigned group, `T`=1
means transient/dynamically-allocated; `P`
([RFC 3306](https://www.rfc-editor.org/rfc/rfc3306)) means the group is
derived from a unicast prefix; `R`
([RFC 3956](https://www.rfc-editor.org/rfc/rfc3956)) means a rendezvous
point address is embedded for PIM-SM. `scop` is the field worth
memorizing: `1`=interface-local, `2`=link-local, `5`=site-local,
`8`=organization-local, `e`=global. `ff02::1` (all-nodes) and `ff02::2`
(all-routers) are the two you'll see constantly. The full addressing
architecture, multicast included, lives in
[RFC 4291](https://www.rfc-editor.org/rfc/rfc4291).

Every unicast/anycast address also has a shadow **solicited-node
multicast** address, built by taking its low 24 bits and appending them
to a fixed prefix:

```
unicast:         2001:db8::1a2b:3c4d:5e6f
low 24 bits:                     4d 5e 6f
solicited-node:  ff02::1:ff4d:5e6f
```

This is the mechanism that lets Neighbor Solicitation avoid broadcast
entirely - see [Neighbor Discovery](#neighbor-discovery). Because the
group is derived from only 24 bits, collisions across unrelated
addresses are possible in theory but rare enough in practice not to
matter on a normal LAN.

Runnable in `demos/01-address-anatomy.sh`.

## SLAAC

Stateless Address Autoconfiguration
([RFC 4862](https://www.rfc-editor.org/rfc/rfc4862)) is how a host gets
a global address without any server. The sequence:

1. Host generates a **tentative** link-local address (`fe80::` + interface
   ID) and runs **Duplicate Address Detection** on it before using it for
   anything - even before joining the network it needs the address for.
2. DAD: send a Neighbor Solicitation with source address `::`
   (unspecified - this is the tell that distinguishes a DAD probe from a
   normal address-resolution NS) and target = the tentative address, to
   that address's solicited-node multicast group. Wait `RetransTimer`
   (default 1000ms). If no NA comes back claiming the address, and no
   other NS shows up doing DAD on the same address, it moves from
   tentative to preferred.
3. Host sends Router Solicitation (or waits for the periodic RA) and
   reads the **Prefix Information Option** out of the RA - see
   [Router Advertisements](#router-advertisements). If the `A` (autonomous)
   flag is set, the host concatenates that prefix with an interface ID to
   build a full address, then DADs *that* too.

RFC 4862 itself is the second-generation spec: the original,
[RFC 1971](https://www.rfc-editor.org/rfc/rfc1971) (1996), was obsoleted
by [RFC 2462](https://www.rfc-editor.org/rfc/rfc2462) (1998), which was
in turn obsoleted by RFC 4862 (2007) - the same three-generation pattern
as Neighbor Discovery and ICMPv6 below, all revised together once early
2000s deployment experience showed where the 1998 specs fell short.

Two ways to generate the interface ID half:

- **EUI-64** - deterministic, derived from the MAC (see
  [Address Anatomy](#address-anatomy)). Stable forever, which means the
  same host is trackable across networks and across time by its interface
  ID alone.
- **Temporary (privacy) addresses** - a pseudo-random interface ID,
  regenerated periodically (Linux defaults: `temp_prefered_lft` 1 day,
  `temp_valid_lft` 7 days), carrying forward an opaque history value so
  successive addresses aren't linkable to each other. The universal/local
  bit is cleared to mark it as not MAC-derived. Originally specified as
  [RFC 3041](https://www.rfc-editor.org/rfc/rfc3041) (January 2001) and
  obsoleted by [RFC 4941](https://www.rfc-editor.org/rfc/rfc4941)
  (September 2007) - a direct response to the realization that a stable,
  MAC-derived address lets any network a laptop joins fingerprint and
  track that specific machine over time, a privacy concern that only
  became concrete once WiFi made "carry your laptop to a different
  network every day" normal. A host normally keeps *both* the EUI-64
  address (for incoming connections) and rotating temporary addresses
  (preferred for outbound connections) live at once - that's the
  `temporary`/`dynamic` flags you see in `ip -6 addr show`.

Runnable in `demos/02-slaac.sh`.

## Neighbor Discovery

NDP ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861)) replaces ARP
and folds in a chunk of what ICMP did for IPv4, all as ICMPv6 message
types. Like SLAAC, it's on its third generation:
[RFC 1970](https://www.rfc-editor.org/rfc/rfc1970) (1996) ->
[RFC 2461](https://www.rfc-editor.org/rfc/rfc2461) (1998) -> RFC 4861
(2007).

| Type | Name | Role |
|---|---|---|
| 133 | Router Solicitation (RS) | "any routers out there?" |
| 134 | Router Advertisement (RA) | prefix, defaults, options |
| 135 | Neighbor Solicitation (NS) | "who has this address?" / DAD probe |
| 136 | Neighbor Advertisement (NA) | "I have it, here's my link-layer addr" |
| 137 | Redirect | "use this other router instead" |

NS/NA layout - both carry the target address plus link-layer-address
options:

```
NS:  Type=135 Code=0 Checksum | Reserved(32) | Target Address(128)
     [Source Link-Layer Address option]

NA:  Type=136 Code=0 Checksum | R S O Reserved(29) | Target Address(128)
     [Target Link-Layer Address option]
```

`R` = sender is a router, `S` = this is a solicited response (vs.
unsolicited/gratuitous), `O` = override an existing cache entry even if
one exists. A gratuitous NA with `O=1` is exactly the primitive that
[NDP spoofing](#attack-lab) abuses - it's the ARP-spoofing equivalent,
and there's no authentication stopping any node on the link from sending
one for any address (Secure Neighbor Discovery,
[RFC 3971](https://www.rfc-editor.org/rfc/rfc3971), specifies a
cryptographic fix, but it never saw meaningful real-world adoption).

The **neighbor cache** (`ip -6 neigh show`, the ARP-table equivalent) is
a real state machine, not just a key-value cache:

```
INCOMPLETE --(NA received)--> REACHABLE --(ReachableTime expires)--> STALE
                                                                        |
                                                          (packet sent to it)
                                                                        v
     REACHABLE <--(NA received)-- PROBE <--(DelayFirstProbeTime expires)-- DELAY
        |
   (unicast NS retries exhausted, no reply)
        v
     removed
```

`STALE` entries are trusted optimistically until you actually need to
send a packet, at which point the host moves to `DELAY` and gives the
upper-layer protocol a window to confirm reachability (e.g. a TCP ACK)
before spending a Neighbor Solicitation to re-verify. That's an
optimization ARP never had.

Runnable in `demos/03-ndp.sh`.

## Router Advertisements

RA is one of the five NDP message types defined in
[RFC 4861](https://www.rfc-editor.org/rfc/rfc4861):

```
Type=134 Code=0 Checksum(16)
Cur Hop Limit(8) | M O H Prf(2) Reserved(3)
Router Lifetime(16)
Reachable Time(32)
Retrans Timer(32)
[Options...]
```

`M` (Managed) = "get your address from DHCPv6, not SLAAC." `O` (Other) =
"get *other* config (DNS, NTP...) from DHCPv6, but SLAAC is fine for the
address itself." `Prf` is a 2-bit router preference (`01`=high,
`00`=medium, `11`=low) used to pick a default router when more than one
answers - added in [RFC 4191](https://www.rfc-editor.org/rfc/rfc4191)
(2005) once multi-router segments in real deployments showed hosts
needed a way to express "prefer this one."

The option that actually delivers a usable prefix is the **Prefix
Information Option**:

```
Type=3 Length=4(*8 octets) Prefix Length(8) L A Reserved1(6)
Valid Lifetime(32)
Preferred Lifetime(32)
Reserved2(32)
Prefix(128)
```

`L` = on-link (packets to this prefix don't need a router), `A` =
autonomous (use this prefix for SLAAC). A prefix can be on-link without
being autonomous and vice versa - routers announce reachability and
address-generation eligibility as independent bits on purpose.

Other common options: **MTU** (type 5, tells the segment's link MTU when
it's non-default), **RDNSS** (type 25,
[RFC 8106](https://www.rfc-editor.org/rfc/rfc8106), DNS server addresses
straight from the RA so a host never needs DHCPv6 just for name
resolution), **Route Information** (type 24,
[RFC 4191](https://www.rfc-editor.org/rfc/rfc4191), "use this router for
this specific prefix" - lets a host learn routes beyond the default
without a routing protocol).

Router Solicitation exists so a host doesn't have to wait out the
periodic RA interval (which can be minutes) on boot - RS multicasts to
`ff02::2` and gets an immediate unicast or multicast RA back.

Runnable in `demos/04-router-advertisement.sh`.

## ICMPv6

IPv6 has no ARP, no broadcast, and no separate ping protocol - errors,
echo, Multicast Listener Discovery, and all of NDP are ICMPv6
([RFC 4443](https://www.rfc-editor.org/rfc/rfc4443)), a deliberate
consolidation of what IPv4 had spread across ICMP, ARP, and IGMP as
three separate protocols. This too is a third-generation spec:
[RFC 1885](https://www.rfc-editor.org/rfc/rfc1885) (1995) ->
[RFC 2463](https://www.rfc-editor.org/rfc/rfc2463) (1998) -> RFC 4443
(2006). Generic header:

```
Type(8) Code(8) Checksum(16) [message body]
```

The checksum covers a **pseudo-header** the same way TCP/UDP do, because
IPv6 itself carries no header checksum at all:

```
Source Address(128) | Destination Address(128) |
Upper-Layer Packet Length(32) | zero(24) | Next Header(8)
```

| Type | Name | Notes |
|---|---|---|
| 1 | Destination Unreachable | code distinguishes no-route / admin-prohibited / addr-unreachable / port-unreachable |
| 2 | Packet Too Big | drives Path MTU Discovery - IPv6 routers never fragment in-flight |
| 3 | Time Exceeded | hop limit hit 0, or reassembly timed out |
| 4 | Parameter Problem | malformed header, or an unrecognized option that demands a reply |
| 128/129 | Echo Request/Reply | ping |
| 130-132 | MLD Query/Report/Done | multicast group membership (v6's IGMP) |
| 133-137 | RS/RA/NS/NA/Redirect | NDP, see above |

Two rules matter for anyone writing firewall rules or attack tooling:
error messages must be rate-limited (RFC 4443 mandates it, implementations
use a token bucket), and a node **must not** generate an ICMPv6 error in
response to another ICMPv6 error, or to a packet sent to a multicast
destination (with narrow exceptions for Packet Too Big and one
Parameter Problem case) - otherwise a single bad multicast packet could
trigger a reply storm from every listener on the segment.

Runnable in `demos/05-icmpv6.sh`.

## Extension Headers

IPv6 moved everything optional out of the fixed header and into a
chain of extension headers, each pointed to by the previous header's
**Next Header** field - the same field IPv4 overloaded as "protocol."
The chain mechanism and every header type below are defined in
[RFC 8200](https://www.rfc-editor.org/rfc/rfc8200) §4:

```
IPv6 header (Next Header=0) -> Hop-by-Hop (Next Header=43) -> Routing
  (Next Header=6) -> TCP
```

RFC 8200 mandates this order when multiple are present:

```
IPv6 -> Hop-by-Hop(0) -> Destination(60, for routing intermediates)
     -> Routing(43) -> Fragment(44) -> AH(51) -> ESP(50)
     -> Destination(60, for final dest) -> upper-layer
```

Every extension header except Fragment shares this generic shape:

```
Next Header(8) | Hdr Ext Len(8, in 8-octet units, excluding first 8) | type-specific data...
```

**Hop-by-Hop / Destination Options** are TLV-encoded inside that
type-specific area: `Option Type(8)` (top 2 bits tell a node what to do
if it doesn't recognize the option - skip, discard silently, discard +
ICMP regardless of destination, or discard + ICMP only if destination
wasn't multicast), `Opt Data Len(8)`, `Opt Data`. `Pad1`/`PadN` options
exist purely to align the header to an 8-octet boundary.

**Routing header** (`Next Header=43`): `Routing Type(8)`,
`Segments Left(8)`, then type-specific data. Type 0 (arbitrary source
routing, originally defined right in RFC 2460) was deprecated by
[RFC 5095](https://www.rfc-editor.org/rfc/rfc5095) (2007) after Philippe
Biondi and Arnaud Ebalard showed it could bounce a packet repeatedly
between colluding routers for a large bandwidth-amplification factor -
see [A Brief History of IPv6](#a-brief-history-of-ipv6) and
[Attack Lab](#attack-lab). Type 4 is the Segment Routing Header (SRv6,
[RFC 8754](https://www.rfc-editor.org/rfc/rfc8754), 2020), a
purpose-built, far more constrained successor used in modern
traffic-engineering deployments.

**Fragment header** is the odd one out - fixed 8 bytes, no `Hdr Ext Len`
field at all:

```
Next Header(8) | Reserved(8) | Fragment Offset(13 bits) Res(2) M(1) | Identification(32)
```

Fragment Offset is in 8-byte units, `M`=1 means more fragments follow.
IPv6 hosts fragment at the source only - routers never do, which is
exactly why Path MTU Discovery (ICMPv6 type 2) exists.

**ESP** ([RFC 4303](https://www.rfc-editor.org/rfc/rfc4303)) breaks the
"Next Header up front" pattern entirely - its Next Header field sits at
the *end* of the header, after the payload and padding, not the
beginning. Any code that walks the extension header chain generically by
reading Next Header first has to special-case ESP. Original IPv6 specs
actually mandated that every conformant node implement IPsec (AH/ESP)
support; that requirement was quietly downgraded from "MUST" to "SHOULD"
in [RFC 6434](https://www.rfc-editor.org/rfc/rfc6434) (2011) once it
became clear almost nobody actually shipped it - one of IPv6's more
famous specification-vs-reality gaps.

Manipulating this chain - reordering headers, splitting it across
fragments, repeating a header type - is the main class of IPv6-specific
firewall/IDS evasion technique. Built hands-on with scapy in
`demos/06-extension-headers.py`; see also [Firewalling](#firewalling) and
`tools/frag6`.

## Multicast

No broadcast in IPv6 - every "reach everyone" job broadcast used to do in
v4 is a specific multicast group in v6 instead (`ff02::1` all-nodes,
`ff02::2` all-routers, plus the per-address solicited-node groups from
[Address Anatomy](#address-anatomy)). Group membership is tracked by
**MLD** ([RFC 2710](https://www.rfc-editor.org/rfc/rfc2710), 1999) and
**MLDv2** ([RFC 3810](https://www.rfc-editor.org/rfc/rfc3810), 2004,
adds source filtering, mirroring IGMPv3) - ICMPv6 types 130 (Query),
131/143 (Report v1/v2), 132 (Done).

The payoff is at the switch: a switch running **MLD snooping** watches
these Query/Report exchanges and only forwards multicast frames - NS/NA
included - out ports that actually asked for that group, instead of
flooding every NDP packet to every port the way an unmanaged switch
would with IPv4 broadcast-based ARP.

Runnable in `demos/07-multicast.sh`.

## DHCPv6

SLAAC only ever hands out an address (plus, via RDNSS, maybe DNS).
DHCPv6 exists for everything that needs actual state on a server:
specific address assignment/tracking, NTP servers, and - the big one -
**prefix delegation**. A home router requesting a routed `/56` or `/60`
from an ISP to hand out to its own LANs does that via an `IA_PD` option;
there's no SLAAC equivalent for "give me a block of prefixes," only
"give me one address." The original spec,
[RFC 3315](https://www.rfc-editor.org/rfc/rfc3315) (2003), was obsoleted
by [RFC 8415](https://www.rfc-editor.org/rfc/rfc8415) (2018), which
folded in what had been a separate prefix-delegation RFC.

Message types worth knowing by number since they show up directly in
packet captures: `SOLICIT`(1), `ADVERTISE`(2), `REQUEST`(3), `RENEW`(5),
`REBIND`(6), `REPLY`(7), `RELEASE`(8), `INFORMATION-REQUEST`(11). Clients
identify themselves with a DUID (link-layer+time, enterprise number, or
bare link-layer), not a client-generated transaction id the way DHCPv4
leans on MAC address alone.

Whether DHCPv6 runs stateful (assigns the address), stateless (SLAAC
handles the address, DHCPv6 only supplies extra options), or not at all
is entirely the RA's M/O flags talking - see
[Router Advertisements](#router-advertisements) and the SLAAC vs DHCPv6
table in [cheatsheet.md](cheatsheet.md).

Runnable in `demos/08-dhcpv6.sh`.

## Transition Mechanisms

Mostly historical at this point, but the addressing tricks are worth
knowing because they still show up:

- **6to4** ([RFC 3056](https://www.rfc-editor.org/rfc/rfc3056), 2001,
  `2002::/16`) embeds a public IPv4 address directly in the next 32 bits
  of the prefix (`2002:AABB:CCDD::/48` for IPv4 `AA.BB.CC.DD`), letting
  any host reach 6to4-space without a tunnel broker. Operational guidance
  turned against it once relay infrastructure proved unreliable
  ([RFC 6343](https://www.rfc-editor.org/rfc/rfc6343), 2011), and
  [RFC 7526](https://www.rfc-editor.org/rfc/rfc7526) (2015) formally
  deprecated its anycast relay mechanism - it has no NAT traversal story
  either, which native dual-stack deployment made moot anyway.
- **Teredo** ([RFC 4380](https://www.rfc-editor.org/rfc/rfc4380), 2006,
  `2001::/32`), designed by Christian Huitema at Microsoft, tunnels IPv6
  inside UDP specifically to survive NAT44, at the cost of embedding a
  lot of state (including the client's NATed port and a flags field)
  directly in the address.
- **NAT64/DNS64** is the one still in real use: DNS64
  ([RFC 6147](https://www.rfc-editor.org/rfc/rfc6147), 2011) synthesizes
  a fake `AAAA` record for a v4-only name under the well-known prefix
  `64:ff9b::/96` ([RFC 6052](https://www.rfc-editor.org/rfc/rfc6052),
  2010), and NAT64 ([RFC 6146](https://www.rfc-editor.org/rfc/rfc6146),
  2011) translates traffic to that synthetic address back into real
  IPv4. This is how a v6-only client network (common on mobile carriers)
  reaches the v4-only internet without every host needing a real v4
  address.

Runnable in `demos/09-transition-mechanisms.sh`.

## Attack Lab

None of NDP or SLAAC carries any authentication by default - anyone on
the link can claim to be a router or claim to own an address, the same
structural gap ARP has always had, just with more moving parts to abuse.
Built inside a `namespaces-fun`-style netns sandbox first,
real-interface capable second - see the authorization banner in the
[repo README](README.md) and `demos/10-attack-lab/README.md`.

- **Rogue RA / SLAAC attack** - send RAs advertising a bogus prefix
  and/or a higher-preference default route (`Prf=01`), pulling victim
  traffic through an attacker-controlled host. `thc-ipv6`'s
  `fake_router6` does the single-shot version, `flood_router6` does the
  DoS version (flood so many distinct RAs that hosts churn through their
  default router list and CPU trying to process them) - this is the
  attack behind the widely-reported "any fully-patched Windows box on
  the segment falls over" incidents that started circulating around 2010-2011.
- **NDP spoofing** - answer Neighbor Solicitations for someone else's
  address with a gratuitous NA (`O=1`, forcing cache override). Direct
  functional equivalent of ARP spoofing; `thc-ipv6`'s `parasite6`
  automates it network-wide. SEND ([RFC 3971](https://www.rfc-editor.org/rfc/rfc3971),
  2005) specifies a cryptographic (CGA-based) fix for exactly this, and
  it exists precisely because this gap was recognized as a problem from
  early on - it just never got meaningfully deployed.
- **Fragmentation abuse** - two distinct hazards, both implemented in
  [`tools/frag6`](tools/frag6) and `demos/10-attack-lab/03-fragmentation-abuse.py`:
  **atomic fragments** ([RFC 6946](https://www.rfc-editor.org/rfc/rfc6946), 2013)
  - a single "fragment" that is actually the whole packet (offset 0,
  M=0), historically used to slip past filters that treat "has a
  Fragment header" as "can't fully inspect this" - and **overlapping
  fragments** ([RFC 5722](https://www.rfc-editor.org/rfc/rfc5722), 2009)
  - two fragments both claiming the same byte range, so which content
  survives reassembly depends on implementation. RFC 5722 mandates that
  a compliant stack discard the entire datagram the instant it detects
  an overlap, specifically because years of IPv4 IDS evasion research
  (Ptacek and Newsham, 1998) showed ambiguous reassembly is unfixable
  any other way. Pairs with the extension-header ordering tricks in
  [Extension Headers](#extension-headers).
- **RA flooding** - flood enough distinct RAs (usually with different
  source addresses/prefixes) that hosts exhaust CPU or memory maintaining
  default-router and prefix lists. `demos/10-attack-lab/04-ra-flood.py`.

Same lineage as the Routing Header Type 0 story in
[A Brief History of IPv6](#a-brief-history-of-ipv6): IPv6's early design
optimized for extensibility and trusted the local link more than
hindsight says it should have, and most of the "attacks" here are just
that trust assumption pointed at itself. Everything in this section is
implemented, not stubbed - see `demos/10-attack-lab/README.md`.

## Firewalling

`ip6tables`/`nftables` gotchas that don't exist in v4-land:

- **ICMPv6 types you must not block on-link**: NS/NA/RS/RA/Redirect
  (133-137) - block these and IPv6 itself stops working, not just
  diagnostics. [RFC 4890](https://www.rfc-editor.org/rfc/rfc4890) (2007)
  is the reference for exactly what a host or transit firewall should
  and shouldn't filter; it also recommends passing Packet Too Big (2)
  and Time Exceeded (3) so PMTUD and traceroute keep working.
- **Extension headers break naive stateless filters** - a filter that
  only inspects the first N bytes assuming a fixed header size, or that
  keys off Next Header in the fixed header without walking the chain,
  can be trivially bypassed by burying the real upper-layer protocol
  behind Hop-by-Hop/Destination Options headers. See
  [Extension Headers](#extension-headers).
- **RA Guard evasion**
  ([RFC 7113](https://www.rfc-editor.org/rfc/rfc7113), 2014) - a
  switch-level RA Guard that only inspects unfragmented ICMPv6 RA
  packets can be defeated by fragmenting the RA itself, or hiding it
  behind extension headers the guard doesn't reassemble/parse before
  making a filtering decision. Correct RA Guard implementations have to
  fully reassemble and walk the header chain first, which is expensive
  enough that not all of them do it. `tools/xdp_ra_guard` is a from-scratch
  implementation that does exactly that - walks the extension header chain
  and drops fragmented ND-shaped traffic per
  [RFC 6980](https://www.rfc-editor.org/rfc/rfc6980) rather than
  reassembling it.

Runnable in `demos/11-firewalling.sh`.

## Capstone

Wire up a v6-only network segment from scratch using nothing but what
the earlier sections covered: netns + veth addressing, radvd for RA,
a resolver reachable over v6 only, and an `ip6tables`/`nftables` ruleset
built from the [Firewalling](#firewalling) must-allow list rather than
copied from a v4 template. Prove it end-to-end by resolving a name and
fetching it with no IPv4 anywhere in the path. Runnable in
`demos/12-capstone.sh`.

## References

### Core specs, in obsoletes order

| Topic | Lineage |
|---|---|
| Base protocol | [RFC 1883](https://www.rfc-editor.org/rfc/rfc1883) (1995) -> [RFC 2460](https://www.rfc-editor.org/rfc/rfc2460) (1998) -> [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200) (2017, Internet Standard) |
| Addressing architecture | [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291) (2006) |
| Neighbor Discovery | [RFC 1970](https://www.rfc-editor.org/rfc/rfc1970) (1996) -> [RFC 2461](https://www.rfc-editor.org/rfc/rfc2461) (1998) -> [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) (2007) |
| SLAAC | [RFC 1971](https://www.rfc-editor.org/rfc/rfc1971) (1996) -> [RFC 2462](https://www.rfc-editor.org/rfc/rfc2462) (1998) -> [RFC 4862](https://www.rfc-editor.org/rfc/rfc4862) (2007) |
| ICMPv6 | [RFC 1885](https://www.rfc-editor.org/rfc/rfc1885) (1995) -> [RFC 2463](https://www.rfc-editor.org/rfc/rfc2463) (1998) -> [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443) (2006) |
| Privacy extensions | [RFC 3041](https://www.rfc-editor.org/rfc/rfc3041) (2001) -> [RFC 4941](https://www.rfc-editor.org/rfc/rfc4941) (2007) |
| DHCPv6 | [RFC 3315](https://www.rfc-editor.org/rfc/rfc3315) (2003) -> [RFC 8415](https://www.rfc-editor.org/rfc/rfc8415) (2018) |
| MLD | [RFC 2710](https://www.rfc-editor.org/rfc/rfc2710) (1999) -> [RFC 3810](https://www.rfc-editor.org/rfc/rfc3810) (2004, MLDv2) |
| Router preference / route info | [RFC 4191](https://www.rfc-editor.org/rfc/rfc4191) (2005) |
| RDNSS option | [RFC 8106](https://www.rfc-editor.org/rfc/rfc8106) (2017) |
| Secure Neighbor Discovery (SEND) | [RFC 3971](https://www.rfc-editor.org/rfc/rfc3971) (2005) |

### Extension headers & security

- [RFC 5095](https://www.rfc-editor.org/rfc/rfc5095) - Deprecation of Type 0 Routing Headers (2007)
- [RFC 8754](https://www.rfc-editor.org/rfc/rfc8754) - Segment Routing Header, SRv6 (2020)
- [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303) - ESP
- [RFC 6434](https://www.rfc-editor.org/rfc/rfc6434) - IPv6 Node Requirements (downgrades mandatory IPsec)
- [RFC 4890](https://www.rfc-editor.org/rfc/rfc4890) - Recommendations for ICMPv6 Filtering
- [RFC 7113](https://www.rfc-editor.org/rfc/rfc7113) - RA-Guard Evasion
- [RFC 6980](https://www.rfc-editor.org/rfc/rfc6980) - Security Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery
- [RFC 5722](https://www.rfc-editor.org/rfc/rfc5722) - Handling of Overlapping IPv6 Fragments
- [RFC 6946](https://www.rfc-editor.org/rfc/rfc6946) - Processing of IPv6 "Atomic" Fragments
- Atlasis, "Attacking IPv6 Implementation Using Fragmentation" (2012)
- Ptacek and Newsham, "Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection" (1998) - the IPv4-era fragmentation/reassembly ambiguity research RFC 5722 exists to close off in IPv6

### Transition mechanisms

- [RFC 3056](https://www.rfc-editor.org/rfc/rfc3056) - 6to4
- [RFC 6343](https://www.rfc-editor.org/rfc/rfc6343) - 6to4 deployment advisory
- [RFC 7526](https://www.rfc-editor.org/rfc/rfc7526) - Deprecating 6to4 anycast relays
- [RFC 4380](https://www.rfc-editor.org/rfc/rfc4380) - Teredo
- [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052) - NAT64/DNS64 well-known prefix
- [RFC 6146](https://www.rfc-editor.org/rfc/rfc6146) - NAT64
- [RFC 6147](https://www.rfc-editor.org/rfc/rfc6147) - DNS64

### History

- [RFC 1550](https://www.rfc-editor.org/rfc/rfc1550) - IPng White Paper Solicitation (1993)
- [RFC 1347](https://www.rfc-editor.org/rfc/rfc1347), [RFC 1710](https://www.rfc-editor.org/rfc/rfc1710), [RFC 1707](https://www.rfc-editor.org/rfc/rfc1707) - the TUBA, SIPP, and CATNIP proposals
- [RFC 1752](https://www.rfc-editor.org/rfc/rfc1752) - the IPng recommendation selecting SIPP (1995)
- [RFC 1190](https://www.rfc-editor.org/rfc/rfc1190) / [RFC 1819](https://www.rfc-editor.org/rfc/rfc1819) - ST-II / ST2+, the protocol that used version number 5
- [RFC 3701](https://www.rfc-editor.org/rfc/rfc3701) - 6bone phaseout plan
- Biondi, Ebalard - "IPv6 Routing Header Security," CanSecWest 2007 (the RH0 amplification attack disclosure)

### Tooling

- [thc-ipv6](https://github.com/vanhauser-thc/thc-ipv6) - the reference offensive IPv6 toolkit (`fake_router6`, `flood_router6`, `parasite6`, and more), source for the attack names cited in [Attack Lab](#attack-lab)
