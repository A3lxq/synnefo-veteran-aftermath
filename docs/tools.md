# Tools you'll use in this box

| Tool | What it's for here |
|---|---|
| curl / browser | Download every evidence file from `/evidence/`. |
| Plain reading + cross-referencing | `auth.log` and `web_access.log` share a timestamp window and an IP address — correlate them by hand. |
| Wireshark or `tshark` | Inspect `capture.pcap` properly (Follow → TCP Stream). `strings capture.pcap` also works for everything this particular capture contains. |
| `grep` / `strings` | Pull plain-text data out of `memory_snapshot.txt` and `disk_image.img`. `disk_image.img` is a raw byte blob, not a mountable filesystem — don't bother trying to mount it, just search its bytes. |
| `ssh` | The one live pivot: log into the still-running host with a credential recovered from the evidence. |
| `sudo -l` + GTFOBins (gtfobins.github.io) | Find and use a sudo misconfiguration once you're logged in. |
| `docker/flagcrypto.py` (ships with this repo) | Decrypt the final artifact once you have its passphrase. |
