#!/bin/bash
set -euo pipefail

: "${CTF_SECRET:?CTF_SECRET must be set}"
export CTF_SECRET

MYSQL_PASSWORD="H@lcyon-Mem0ry!"   # only ever disclosed via memory_snapshot.txt

mkdir -p /var/log/supervisor
VENV=/opt/venv

$VENV/bin/python3 /opt/make_evidence.py
chown -R www-data:www-data /var/www/evidence
find /var/www/evidence -type f -exec chmod 644 {} +

getflag() { $VENV/bin/python3 -c "import sys; sys.path.insert(0,'/opt/shared'); from generate_flags import flag_for; print(flag_for('$CTF_SECRET', $1))"; }
getsecret() { $VENV/bin/python3 -c "import sys; sys.path.insert(0,'/opt/shared'); from generate_flags import secret_for; print(secret_for('$CTF_SECRET', '$1'))"; }

# --- the live pivot host ----------------------------------------------------
echo "svc-monitor:$MYSQL_PASSWORD" | chpasswd
getflag 8 > /home/svc-monitor/flag8.txt
chown svc-monitor:svc-monitor /home/svc-monitor/flag8.txt
chmod 600 /home/svc-monitor/flag8.txt

# Stage 9: sudo misconfiguration (NOPASSWD on a GTFOBins-listed binary).
echo "svc-monitor ALL=(root) NOPASSWD: /usr/bin/find" > /etc/sudoers.d/svc-monitor
chmod 440 /etc/sudoers.d/svc-monitor

getflag 9 > /root/flag9.txt
chmod 600 /root/flag9.txt

DOSSIER_PW=$(getsecret dossier_password)
F10=$(getflag 10)
echo -n "$F10" > /tmp/flag10_plain.txt
$VENV/bin/python3 /opt/shared/flagcrypto.py encrypt "$DOSSIER_PW" /tmp/flag10_plain.txt /root/dossier.enc
rm -f /tmp/flag10_plain.txt
chmod 600 /root/dossier.enc

ssh-keygen -A >/dev/null 2>&1 || true

echo "[entrypoint] Aftermath ready."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
