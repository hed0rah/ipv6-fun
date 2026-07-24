# 10 - attack lab

The module where SLAAC and NDP's complete lack of authentication get
abused on purpose. Everything here is **real-interface capable** - see
the authorization banner in the repo root [README](../../README.md)
before running any of it outside a throwaway lab.

## Planned sandbox

Built on the network namespace + veth pattern from
[namespaces-fun](https://github.com/hed0rah/namespaces-fun): two or three
netns joined by veth pairs, one acting as a legitimate router (radvd), the
others as victims. Attacks run inside this sandbox first - zero blast
radius - before ever pointing them at a real interface.

## Planned attacks

- **rogue RA / SLAAC attack** - advertise a bogus prefix and/or become the
  default route via a higher-preference RA, redirect traffic through an
  attacker-controlled host (the `thc-ipv6` `fake_router6`/`flood_router6`
  playbook)
- **NDP spoofing** - answer Neighbor Solicitations for someone else's
  address, the direct ARP-spoofing equivalent for v6
- **fragmentation abuse** - atomic fragments and overlapping fragments to
  slip payloads past stateless filters (pairs with `tools/frag6`)
- **RA flooding** - exhaust host neighbor-cache/RA-processing resources,
  the classic "Windows falls over" IPv6 DoS from ~2011

Not yet implemented. Offensive code here gets written deliberately, with
warnings and a default-safe (netns-only) mode, not rushed in during a
scaffolding pass.
