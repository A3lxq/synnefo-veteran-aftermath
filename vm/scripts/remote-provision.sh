#!/usr/bin/env bash
# remote-provision.sh — runs INSIDE the guest. Native build: real
# nginx (evidence drop) + openssh-server (the one live pivot host), no
# Docker. Entirely self-contained. Idempotent.
set -euo pipefail

: "${RELEASE_SECRET:?RELEASE_SECRET must be passed in (never hardcode it here -- this script is public)}"
MYSQL_PASSWORD="H@lcyon-Mem0ry!"   # only ever disclosed via memory_snapshot.txt

echo "== Python venv + deps (scapy for the pcap, cryptography for the final decrypt) =="
sudo mkdir -p /opt/venv
sudo python3 -m venv /opt/venv
sudo /opt/venv/bin/pip install -q --no-cache-dir --retries 10 --timeout 120 \
    scapy==2.6.1 cryptography==43.0.3

echo "== Staging the evidence-building tools =="
sudo mkdir -p /opt/shared
sudo tee /opt/shared/generate_flags.py >/dev/null <<'PY_EOF'
import hmac
import hashlib

BOX_ID = "veteran-aftermath"


def flag_for(secret: str, n: int) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:{n}".encode(), hashlib.sha256).hexdigest()
    return f"HLC{{{digest[:10]}}}"


def secret_for(secret: str, label: str) -> str:
    digest = hmac.new(secret.encode(), f"{BOX_ID}:secret:{label}".encode(), hashlib.sha256).hexdigest()
    return digest[:20]
PY_EOF

sudo tee /opt/shared/flagcrypto.py >/dev/null <<'PY_EOF'
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"HLCX1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_bytes(passphrase: str, plaintext: bytes) -> bytes:
    import os
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return MAGIC + salt + nonce + ct


def decrypt_bytes(passphrase: str, blob: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("Not a recognized flagcrypto file (bad magic).")
    rest = blob[len(MAGIC):]
    salt, nonce, ct = rest[:SALT_LEN], rest[SALT_LEN:SALT_LEN + NONCE_LEN], rest[SALT_LEN + NONCE_LEN:]
    key = _derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] not in ("encrypt", "decrypt"):
        print(__doc__)
        sys.exit(1)
    mode, passphrase, infile, outfile = sys.argv[1:5]
    with open(infile, "rb") as f:
        data = f.read()
    result = encrypt_bytes(passphrase, data) if mode == "encrypt" else decrypt_bytes(passphrase, data)
    if outfile == "-":
        sys.stdout.buffer.write(result)
    else:
        with open(outfile, "wb") as f:
            f.write(result)
PY_EOF

sudo tee /opt/make_evidence.py >/dev/null <<'PY_EOF'
import os
import sys

sys.path.insert(0, "/opt/shared")
from generate_flags import flag_for, secret_for  # noqa: E402
from scapy.all import Ether, IP, TCP, wrpcap  # noqa: E402

SECRET = os.environ["CTF_SECRET"]
EVIDENCE_DIR = "/var/www/html/evidence"
ATTACKER_IP = "203.0.113.44"
MYSQL_PASSWORD = "H@lcyon-Mem0ry!"


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


def build_old_creds_honeypot():
    with open(f"{EVIDENCE_DIR}/old_creds_dump.txt", "w") as f:
        f.write(
            "recovered from a decommissioned backup, rotated out long before\n"
            "this incident -- do not waste time on these, they work nowhere:\n"
            "admin / Winter2019!\n"
            "backup_svc / B4ckup-Legacy\n"
        )


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
PY_EOF

echo "== nginx: evidence drop at /evidence/ =="
sudo mkdir -p /var/www/html/evidence
sudo tee /etc/nginx/sites-available/default >/dev/null <<'EOF'
server {
    listen 80 default_server;
    root /var/www/html;
    location /evidence/ {
        autoindex on;
    }
    location = / {
        return 200 "Aftermath -- evidence drop. See /evidence/\n";
    }
}
EOF

echo "== Building the evidence =="
sudo CTF_SECRET="$RELEASE_SECRET" /opt/venv/bin/python3 /opt/make_evidence.py
sudo chown -R www-data:www-data /var/www/html/evidence
sudo find /var/www/html/evidence -type f -exec chmod 644 {} +

getflag() { /opt/venv/bin/python3 -c "import sys; sys.path.insert(0,'/opt/shared'); from generate_flags import flag_for; print(flag_for('$RELEASE_SECRET', $1))"; }
getsecret() { /opt/venv/bin/python3 -c "import sys; sys.path.insert(0,'/opt/shared'); from generate_flags import secret_for; print(secret_for('$RELEASE_SECRET', '$1'))"; }

echo "== The live pivot host (flags 8, 9) =="
sudo id -u svc-monitor >/dev/null 2>&1 || sudo useradd -m -s /bin/bash svc-monitor
echo "svc-monitor:$MYSQL_PASSWORD" | sudo chpasswd
getflag 8 | sudo tee /home/svc-monitor/flag8.txt >/dev/null
sudo chown svc-monitor:svc-monitor /home/svc-monitor/flag8.txt
sudo chmod 600 /home/svc-monitor/flag8.txt

echo "== Enabling SSH password auth for svc-monitor only =="
sudo tee /etc/ssh/sshd_config.d/90-svc-monitor-password-auth.conf >/dev/null <<'EOF'
Match User svc-monitor
    PasswordAuthentication yes
EOF
sudo chmod 644 /etc/ssh/sshd_config.d/90-svc-monitor-password-auth.conf
sudo sshd -t

echo "== Sudo misconfiguration -> root (flag 9) =="
echo "svc-monitor ALL=(root) NOPASSWD: /usr/bin/find" | sudo tee /etc/sudoers.d/svc-monitor >/dev/null
sudo chmod 440 /etc/sudoers.d/svc-monitor
getflag 9 | sudo tee /root/flag9.txt >/dev/null
sudo chmod 600 /root/flag9.txt

echo "== Final dossier (flag 10, passphrase recovered from the disk image) =="
DOSSIER_PW=$(getsecret dossier_password)
F10=$(getflag 10)
echo -n "$F10" | sudo tee /tmp/flag10_plain.txt >/dev/null
sudo /opt/venv/bin/python3 /opt/shared/flagcrypto.py encrypt "$DOSSIER_PW" /tmp/flag10_plain.txt /root/dossier.enc
sudo rm -f /tmp/flag10_plain.txt
sudo chmod 600 /root/dossier.enc

echo "== Restarting services =="
sudo systemctl restart nginx
sudo systemctl enable nginx
sudo pkill -9 -f 'sshd: /usr/sbin/sshd -D \[listener\]' 2>/dev/null || true
sleep 1
sudo systemctl restart ssh
sudo systemctl enable ssh

echo "Done."
