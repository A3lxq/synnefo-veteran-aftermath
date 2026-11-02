# Organizer manifest — Aftermath (Veteran)

Keep this file (and this whole `organizer/` directory) off any
player-facing host. Flag *values* are never written here — re-derive
them from the deployment's `CTF_SECRET`
(HMAC-SHA256("veteran-aftermath:N", secret), first 10 hex chars,
wrapped `HLC{...}`).

Mostly forensic artifacts, not a live multi-stage exploit chain: a
single container serves a static evidence drop over HTTP and runs one
SSH service, the box's one "offensive pivot."

| # | Difficulty | Concept taught | Primary tool(s) | Where it lives |
|---|---|---|---|---|
| 1 | Easy | Reading a provided document | curl/browser | `case_manifest.txt` |
| 2 | Easy | Reading an auth log | curl/browser | `auth.log` |
| 3 | Medium | Log correlation across two sources (shared IP + time window) | manual cross-referencing | `web_access.log` |
| 4/5 | Medium | Packet capture analysis | Wireshark / `tshark` / `strings` | `capture.pcap` |
| 6 | Medium/Hard | Memory/process-list analysis, credentials leaked in a command line | `grep`/`strings` on `memory_snapshot.txt` | leaked `mysql -p...` invocation |
| 7 | Hard | Raw disk/unallocated-space string carving | `strings -a` on `disk_image.img` | recovered deleted note |
| 8 | Hard | The offensive pivot: credential reuse to gain real access | `ssh` | `svc-monitor`'s home directory |
| 9 | Hard | sudo NOPASSWD misconfiguration -> privilege escalation | `sudo -l`, GTFOBins `find` entry | `/root/flag9.txt` |
| 10 | Capstone | Combining a passphrase recovered mid-investigation with the final artifact | `flagcrypto.py` (ships to players) | `/root/dossier.enc` |

## Honeypots (never flag-shaped, cost time only)
- `evidence/old_creds_dump.txt` — plausible but explicitly inert decoy
  credentials, unrelated to the real pivot password.

## Fixed design constants (intentional, not secret-derived)
- Attacker IP correlated across `auth.log`/`web_access.log`:
  `203.0.113.44` (a real reserved documentation-only IP, never a real
  host).
- `svc-monitor`'s password == the mysql password leaked in
  `memory_snapshot.txt`: `H@lcyon-Mem0ry!` — credential reuse is the
  deliberate lesson for stage 8, same as elsewhere in this series.
- Privesc: `svc-monitor ALL=(root) NOPASSWD: /usr/bin/find` (sudoers
  misconfiguration — a different mechanism from this series' earlier
  SUID-bit privescs, same GTFOBins binary, different category of bug).
- Final passphrase (`dossier.enc`'s key) is disclosed only via the
  disk-image carving step (flag 7), reinforcing "read every artifact,
  not just the obvious ones."
- `disk_image.img` is NOT a mountable filesystem — it's a raw byte
  blob with random padding around a plaintext fragment, deliberately
  simplified from a real forensic disk image so the lesson (search raw
  bytes for recoverable data) doesn't require specialized carving tools.
  Documented as such in `STORY.md`/`docs/tools.md` so nobody wastes time
  trying to mount it.
