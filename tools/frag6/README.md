# frag6

Atomic and overlapping IPv6 fragmentation tool - the classic
firewall/IDS evasion technique: split a packet so the first fragment
looks benign to a stateless filter, then let a later overlapping
fragment overwrite the parts that matter once reassembled.

Real-interface capable, like the rest of this repo's arsenal (see the
authorization banner in the [repo README](../../README.md)). Pairs with
`demos/10-attack-lab` and the fragmentation-abuse section of
`demos/11-firewalling.sh`.

## Planned interface

```
frag6 --dst fd00::2 --mode atomic --payload icmp6-echo
frag6 --dst fd00::2 --mode overlap --frag-size 8 --payload <raw-hex>
```

Not yet implemented - this is offensive/evasion code and gets its own
focused implementation pass rather than being rushed into a scaffold.
