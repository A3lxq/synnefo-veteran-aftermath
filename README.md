# Case File 7 (Veteran) — Aftermath

Part of **The Halcyon Protocol** CTF series. This box stands alone — you do
not need any other box in the series to play it.

> See [`STORY.md`](STORY.md) for the full case file.

## What this is

Not a live system to exploit, mostly — **a forensic evidence drop**: an
auth log, a web access log, a packet capture, a process-list snapshot,
and a raw disk excerpt, all from the same incident window. 10 flags, no
decoys, found by correlating evidence across files rather than chaining
exploits. The last few flags require one genuine offensive pivot: using
a credential you recover from the evidence to actually log into the one
host still running.

**This machine is intentionally vulnerable. Run it only on an isolated
network.**

## Running it

Download the `.ova` from this repo's [Releases](../../releases) page
and import it into VirtualBox (File > Import Appliance) or VMware
Workstation/Fusion (File > Open). It boots and sets itself up
automatically — nothing to configure. See [`vm/README.md`](vm/README.md)
for details and for rebuilding it from source.

There is no Docker build in this repo (an earlier one was removed; a
Docker version may be added back separately).

## Flag format

`HLC{xxxxxxxxxx}` — submit exactly as found.

## Rules

- No decoy flags: everything matching the flag format is real and counts.
- Some things in this box are honeypots — red herrings that cost you time,
  not flags.
- Don't attack this box over a shared or public network.

## More

- [`STORY.md`](STORY.md) — the in-universe case file
- [`docs/hints.md`](docs/hints.md) — progressive hints
- [`docs/tools.md`](docs/tools.md) — what each tool is for
- [`docs/writeup/WRITEUP.md`](docs/writeup/WRITEUP.md) — full spoiler walkthrough
- [`flags/generate_flags.py`](flags/generate_flags.py) — the per-deployment flag derivation scheme, used by `organizer/verify.py`
