#!/usr/bin/env sh
# Bunkr one-shot installer. Run from the repo folder:  ./install.sh
set -eu
command -v docker >/dev/null 2>&1 || { echo "Docker is required: https://docs.docker.com/engine/install/"; exit 1; }
printf "Domain for HTTPS (e.g. chat.example.com, empty = plain http on :8080): "
read -r DOMAIN || DOMAIN=""
if [ -n "$DOMAIN" ]; then
  echo "BUNKR_DOMAIN=$DOMAIN" > .env
  docker compose --profile tls up -d --build
  URL="https://$DOMAIN"
else
  docker compose up -d --build
  URL="http://$(hostname -I 2>/dev/null | awk '{print $1}'):8080"
fi
echo "Waiting for Bunkr to start..."
for _ in $(seq 1 30); do
  CODE=$(docker compose logs bunkr 2>/dev/null | grep -A1 "SETUP CODE" | tail -1 | awk '{print $NF}')
  [ -n "${CODE:-}" ] && break
  sleep 1
done
echo
echo "  Bunkr is up:  $URL"
[ -n "${CODE:-}" ] && echo "  Admin setup code:  $CODE"
echo
