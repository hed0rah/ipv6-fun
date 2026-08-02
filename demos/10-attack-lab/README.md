# 10 - attack lab

The module where SLAAC and NDP's complete lack of authentication get
abused on purpose. Real-interface capable - see the authorization
banner in the [repo README](../../README.md) before pointing any of
this at something you don't own or aren't authorized to test.

## Sandbox

`lab-setup.sh` builds a throwaway two-namespace segment
(`v6lab-victim` / `v6lab-attacker`, joined by a single veth pair - the
same pattern as [namespaces-fun](https://github.com/hed0rah/namespaces-fun)'s
demo 03) with static baseline addressing on `fd00:6:cafe::/64` and
`accept_ra` turned on for the victim. `teardown.sh` tears it down.

```bash
sudo ./lab-setup.sh
# ... run attacks from the attacker namespace, inspect state from the victim's ...
sudo ./teardown.sh
```

## Attacks

All four are real, working implementations (Python + scapy) - not
stubs. Each is a from-scratch version of a well-known
[thc-ipv6](https://github.com/vanhauser-thc/thc-ipv6) tool; see
[deep-dive.md](../../deep-dive.md#attack-lab) for the protocol-level
background and RFC citations.

| Script | Attack | thc-ipv6 equivalent |
|---|---|---|
| `01-rogue-ra.py` | rogue RA advertising a bogus, high-preference prefix | `fake_router6` |
| `02-ndp-spoof.py` | gratuitous NA claiming ownership of an address | `parasite6` |
| `03-fragmentation-abuse.py` | atomic (RFC 6946) and overlapping (RFC 5722) fragments | (various frag tools) |
| `04-ra-flood.py` | many distinct RAs to exhaust a host's RA-processing | `flood_router6` |

Run them from the attacker namespace, watch the victim from another
terminal:

```bash
sudo ip netns exec v6lab-attacker python3 01-rogue-ra.py --iface veth-attacker
sudo ip netns exec v6lab-victim ip -6 route show
```

`03-fragmentation-abuse.py` is the quick-iteration scapy version of
[`tools/frag6`](../../tools/frag6) - the from-scratch raw-socket C tool
that builds the same two fragment shapes by hand, plus resolves the
destination's MAC itself via real Neighbor Discovery instead of relying
on the kernel's routing/ARP-equivalent stack.

## Requirements

- Linux, root, `ip netns` support
- Python 3 + `scapy`
