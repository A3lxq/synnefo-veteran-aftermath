"""
Builds every evidence artifact for this box from the per-deployment
CTF_SECRET. Run once at container start (entrypoint.sh); nothing here
is baked into the image.
"""
import os
import sys

sys.path.insert(0, "/opt/shared")
from generate_flags import flag_for, secret_for  # noqa: E402
from scapy.all import Ether, IP, TCP, wrpcap  # noqa: E402

SECRET = os.environ["CTF_SECRET"]
EVIDENCE_DIR = "/var/www/evidence"
ATTACKER_IP = "203.0.113.44"
MYSQL_PASSWORD = "H@lcyon-Mem0ry!"  # disclosed only via memory_snapshot.txt


def flag(n):
    return flag_for(SECRET, n)


def build_manifest():
    with open(f"{EVIDENCE_DIR}/case_manifest.txt", "w") as f:
        f.write(f"""HALCYON DYNAMICS -- INCIDENT RESPONSE
Case reference: AFTERMATH-2024-0311
Evidence intake sheet

Items recovered from the Annex fileserver the night Priya Okonkwo-Reyes'
access was revoked. Chain of custody preserved; items below are exact
copies, not summaries.

Evidence reference: {flag(1)}

Items:
  1. auth.log           -- SSH authentication log
  2. web_access.log      -- web server access log, same time window
  3. capture.pcap        -- network capture, same time window
  4. memory_snapshot.txt -- captured process list from the live host
  5. disk_image.img      -- raw sector export, partial (deleted-file remnants)

Analyst note: times below are all in the same timezone. Start with
what's easy to correlate -- a single IP address shows up in more than
one of these.
""")


def build_auth_log():
    flag2 = flag(2)
    with open(f"{EVIDENCE_DIR}/auth.log", "w") as f:
        f.write(f"""Mar 11 02:10:11 annex-fileserver sshd[1801]: Accepted publickey for ops from 10.40.0.21 port 51200 ssh2
Mar 11 02:12:45 annex-fileserver sshd[1809]: Failed password for root from 198.51.100.9 port 40112 ssh2
Mar 11 02:13:58 annex-fileserver sshd[1815]: Failed password for admin from {ATTACKER_IP} port 51513 ssh2
Mar 11 02:14:02 annex-fileserver sshd[1823]: Accepted password for svc-monitor from {ATTACKER_IP} port 51514 ssh2 ref={flag2}
Mar 11 02:19:40 annex-fileserver sshd[1823]: pam_unix(sshd:session): session closed for user svc-monitor
Mar 11 02:40:03 annex-fileserver sshd[1850]: Accepted publickey for ops from 10.40.0.21 port 51290 ssh2
""")


def build_old_creds_honeypot():
    # Honeypot: a plausible-looking leftover credential dump, explicitly
    # inert. Never referenced by anything else, costs time only.
    with open(f"{EVIDENCE_DIR}/old_creds_dump.txt", "w") as f:
        f.write(
            "recovered from a decommissioned backup, rotated out long before\n"
            "this incident -- do not waste time on these, they work nowhere:\n"
            "admin / Winter2019!\n"
            "backup_svc / B4ckup-Legacy\n"
        )


def build_web_log():
    flag3 = flag(3)
    with open(f"{EVIDENCE_DIR}/web_access.log", "w") as f:
        f.write(f"""10.40.0.21 - - [11/Mar/2024:02:05:11 +0000] "GET / HTTP/1.1" 200 512
{ATTACKER_IP} - - [11/Mar/2024:02:13:50 +0000] "GET /login HTTP/1.1" 200 349
{ATTACKER_IP} - - [11/Mar/2024:02:14:05 +0000] "GET /admin/export?token={flag3} HTTP/1.1" 200 2048
{ATTACKER_IP} - - [11/Mar/2024:02:14:09 +0000] "GET /admin/export/secrets.txt HTTP/1.1" 200 884
10.40.0.21 - - [11/Mar/2024:02:41:00 +0000] "GET /dashboard HTTP/1.1" 200 1203
""")


def build_pcap():
    flag4 = flag(4)
    flag5 = flag(5)
    http_resp_1 = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        f"<html><!-- export ref {flag4} --></html>\r\n"
    ).encode()
    secrets_txt = (
        f"recovered secrets.txt export\n"
        f"{flag5}\n"
        f"pivot host: aftermath-host, port 22\n"
        f"(no credentials written here -- check the memory snapshot)\n"
    )
    http_resp_2 = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        f"{secrets_txt}"
    ).encode()

    pkt1 = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=ATTACKER_IP, dst="10.40.0.5")
        / TCP(sport=51514, dport=80, flags="PA", seq=1, ack=1)
        / http_resp_1
    )
    pkt2 = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=ATTACKER_IP, dst="10.40.0.5")
        / TCP(sport=51516, dport=80, flags="PA", seq=1, ack=1)
        / http_resp_2
    )
    wrpcap(f"{EVIDENCE_DIR}/capture.pcap", [pkt1, pkt2])


def build_memory_snapshot():
    flag6 = flag(6)
    with open(f"{EVIDENCE_DIR}/memory_snapshot.txt", "w") as f:
        f.write(f"""Captured process list -- aftermath-host, 2024-03-11 02:17 UTC
(partial, captured by the on-call responder before the host was isolated)

USER       PID  COMMAND
root         1  /sbin/init
root       203  /usr/sbin/sshd -D
svc-monitor 980 /usr/bin/python3 /opt/monitor/agent.py --token={flag6}
root      1042  mysqld --datadir=/var/lib/mysql
svc-monitor 1055 mysql -u root -p{MYSQL_PASSWORD} -e "SELECT * FROM audit_log LIMIT 1"
root      1080  /usr/sbin/cron
""")


def build_disk_image():
    flag7 = flag(7)
    dossier_pw = secret_for(SECRET, "dossier_password")
    recovered_note = (
        f"-- recovered fragment, unallocated space --\n"
        f"note to self: moved the real evidence before IT got here.\n"
        f"{flag7}\n"
        f"if anyone ever recovers this: the recovery passphrase is {dossier_pw}\n"
        f"-- end fragment --\n"
    ).encode()
    # Pad with non-text bytes on both sides, same spirit as real
    # unallocated-space carving: the useful bytes sit inside noise.
    import os as _os
    with open(f"{EVIDENCE_DIR}/disk_image.img", "wb") as f:
        f.write(_os.urandom(4096))
        f.write(recovered_note)
        f.write(_os.urandom(4096))


if __name__ == "__main__":
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    build_manifest()
    build_old_creds_honeypot()
    build_auth_log()
    build_web_log()
    build_pcap()
    build_memory_snapshot()
    build_disk_image()
    print("Evidence built.")
