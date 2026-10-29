#!/usr/bin/env bash
# Compatibility entrypoint. Both profiles form one controlled experiment now.
set -euo pipefail
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
docker build -t mqtt-security-lab:local ./lab
mkdir -p runtime
docker run --rm --user 0:0 -v "$(pwd)/runtime:/runtime" mqtt-security-lab:local python provision.py
if [ ! -f runtime/passwords-hashed ]; then
  for profile in baseline hardened; do
    docker run --rm --user 0:0 -v "$(pwd)/runtime/${profile}-broker:/credentials" eclipse-mosquitto:2.0.22 sh -c 'chmod 644 /credentials/passwd && mosquitto_passwd -U /credentials/passwd && chmod 444 /credentials/passwd'
  done
  echo done > runtime/passwords-hashed
fi
docker compose up -d --build --wait
echo 'Open http://localhost:8080/dashboard; generated login: runtime/login.txt'
