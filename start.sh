#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -f .env ]; then
    echo "No .env found — generating one with a fresh CTF_SECRET."
    echo "CTF_SECRET=$(openssl rand -hex 32)" > .env
fi
docker compose up -d --build
echo
echo "Evidence drop: http://localhost:8007/evidence/"
echo "Pivot host SSH: ssh -p 2207 svc-monitor@localhost (you need to find the password)"
