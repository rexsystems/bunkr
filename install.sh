#!/usr/bin/env sh
# Bunkr one-shot installer. Run from the repo folder:  ./install.sh
set -eu
command -v docker >/dev/null 2>&1 || { echo "Docker is required: https://docs.docker.com/engine/install/"; exit 1; }
printf "Domain for HTTPS (e.g. chat.example.com, empty = plain http on :8080): "
read -r DOMAIN || DOMAIN=""
PROFILES=""
: > .env
if [ -n "$DOMAIN" ]; then
  echo "BUNKR_DOMAIN=$DOMAIN" >> .env
  PROFILES="--profile tls"
  printf "Run a TURN relay so voice/video calls work across all networks? [Y/n]: "
  read -r TURN || TURN="y"
  case "$TURN" in
    n|N) ;;
    *)
      SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
      {
        echo "BUNKR_TURN_SECRET=$SECRET"
        echo "BUNKR_TURN_URLS=turn:$DOMAIN:3478?transport=udp,turn:$DOMAIN:3478?transport=tcp"
        echo "BUNKR_STUN_URLS=stun:$DOMAIN:3478"
      } >> .env
      PROFILES="$PROFILES --profile calls"
      echo "  -> open UDP/TCP 3478 and UDP 49160-49260 in your firewall."
      ;;
  esac
  URL="https://$DOMAIN"
else
  URL="http://$(hostname -I 2>/dev/null | awk '{print $1}'):8080"
fi
# shellcheck disable=SC2086
docker compose $PROFILES up -d --build
echo "Waiting for Bunkr to start..."
CODE=""
for _ in $(seq 1 60); do
  CODE=$(docker compose logs bunkr 2>/dev/null | grep -A1 "SETUP CODE" | tail -1 | awk '{print $NF}')
  [ -n "$CODE" ] && break
  sleep 1
done
echo
echo "  Bunkr is up:  $URL"
[ -n "$CODE" ] && echo "  Admin setup code:  $CODE"
echo
