#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

KEY="keys/ctfbuilder_ed25519"
PORT=2207
HOST="ctfbuilder@127.0.0.1"
SSH_OPTS=(-i "$KEY" -p "$PORT" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)
RELEASE_SECRET=$(cat ../organizer/release-secret.txt)
MYSQL_PASSWORD="H@lcyon-Mem0ry!"

SSH() { ssh "${SSH_OPTS[@]}" "$HOST" "$@"; }
SSH_SVC() { ssh "${SSH_OPTS[@]}" "$HOST" "sshpass -p '$MYSQL_PASSWORD' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null svc-monitor@localhost \"$1\""; }

check() {
    local n="$1" got="$2"
    local want
    want=$(python3 -c "
import hmac, hashlib
d = hmac.new('$RELEASE_SECRET'.encode(), f'veteran-aftermath:$n'.encode(), hashlib.sha256).hexdigest()
print(f'HLC{{{d[:10]}}}')")
    if [ "$got" = "$want" ]; then
        echo "flag $n: OK ($got)"
    else
        echo "flag $n: MISMATCH got='$got' want='$want'" >&2
        exit 1
    fi
}

F1=$(SSH "curl -s http://localhost/evidence/case_manifest.txt | grep -oE 'HLC\{[a-f0-9]{10}\}'")
check 1 "$F1"

F2=$(SSH "curl -s http://localhost/evidence/auth.log | grep -oE 'HLC\{[a-f0-9]{10}\}'")
check 2 "$F2"

F3=$(SSH "curl -s http://localhost/evidence/web_access.log | grep -oE 'HLC\{[a-f0-9]{10}\}'")
check 3 "$F3"

SSH "curl -s http://localhost/evidence/capture.pcap -o /tmp/capture.pcap"
PCAP_FLAGS=$(SSH "strings /tmp/capture.pcap | grep -oE 'HLC\{[a-f0-9]{10}\}'")
F4=$(echo "$PCAP_FLAGS" | sed -n '1p')
check 4 "$F4"
F5=$(echo "$PCAP_FLAGS" | sed -n '2p')
check 5 "$F5"

MEM=$(SSH "curl -s http://localhost/evidence/memory_snapshot.txt")
F6=$(echo "$MEM" | grep -oE 'HLC\{[a-f0-9]{10}\}')
check 6 "$F6"

SSH "curl -s http://localhost/evidence/disk_image.img -o /tmp/disk_image.img"
DISK=$(SSH "strings -a /tmp/disk_image.img")
F7=$(echo "$DISK" | grep -oE 'HLC\{[a-f0-9]{10}\}')
check 7 "$F7"
DOSSIER_PW=$(echo "$DISK" | sed -n 's/.*recovery passphrase is \([a-f0-9]*\).*/\1/p')

F8=$(SSH_SVC 'cat flag8.txt')
check 8 "$F8"

F9=$(SSH_SVC 'sudo find /root/flag9.txt -exec cat {} \;')
check 9 "$F9"

B64=$(SSH_SVC 'sudo find /root/dossier.enc -exec base64 -w0 {} \;')
echo "$B64" | tr -d '\n' | base64 -d > /tmp/veteran_dossier.enc

# Decrypt locally with an inline copy of the same scheme (flagcrypto.py
# lives embedded in remote-provision.sh for the guest, not as a
# separate file in this repo's vm/, so re-derive it here instead).
F10=$(python3 -c "
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b'HLCX1'
with open('/tmp/veteran_dossier.enc', 'rb') as f:
    blob = f.read()
rest = blob[len(MAGIC):]
salt, nonce, ct = rest[:16], rest[16:28], rest[28:]
key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive('$DOSSIER_PW'.encode())
print(AESGCM(key).decrypt(nonce, ct, None).decode())
")
check 10 "$F10"
rm -f /tmp/veteran_dossier.enc

echo
echo "All 10 flags verified end-to-end."
