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

## Requirements

- Docker + Docker Compose
- A player machine with: `curl`/browser, Wireshark or `tshark` (`strings`
  also works for everything in this box's pcap), `grep`/`strings`, an
  SSH client

## Starting the box

```
./start.sh
```
Generates a fresh `.env` with a random per-deployment secret and brings
the stack up.

- Evidence drop: http://localhost:8007/evidence/
- Pivot host SSH: `ssh -p 2207 svc-monitor@localhost` (find the password
  in the evidence first)

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
