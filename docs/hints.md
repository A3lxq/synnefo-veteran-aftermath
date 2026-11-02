# Hints (progressive — try to only read as far as you need)

**Flag 1** — Just read `case_manifest.txt`.

**Flag 2** — Read `auth.log`. One line stands out from the rest —
not because it's hidden, but because of who it's for and where it's from.

**Flag 3** — The same IP address that shows up in `auth.log` also shows
up in `web_access.log`, around the same time. What did it request?

**Flag 4/5** — `capture.pcap` has two separate HTTP exchanges worth
looking at. `strings capture.pcap` gets you both without needing to
reconstruct the streams properly, though Wireshark's "Follow TCP
Stream" is the more realistic way to do it.

**Flag 6** — `memory_snapshot.txt` is a process list. One line includes
a command's full arguments — command lines sometimes leak passwords
that way in the real world, and this one does too.

**Flag 7** — `disk_image.img` isn't a filesystem you can mount — it's
raw bytes. Something readable is buried in there; a plain string-search
tool will find it.

**Flag 8** — You now have a password. Is there anything in this box
still listening for a login?

**Flag 9** — Once you're in, check what you're allowed to run as
root without a password (`sudo -l`). If it's a common utility, look it
up on GTFOBins.

**Flag 10** — Something you found while carving through the disk image
wasn't just a flag.
