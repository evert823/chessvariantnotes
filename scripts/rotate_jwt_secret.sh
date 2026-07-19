#!/usr/bin/env bash
set -eu

ENV_FILE="${1:-.env}"

if [ ! -f "$ENV_FILE" ]; then
  echo "Error: $ENV_FILE not found"
  exit 1
fi

# Generate new secret
NEW_SECRET="$(openssl rand -base64 32 | tr -d '\n')"

# Replace existing key, or append if missing
if grep -q '^JWT_SECRET_KEY=' "$ENV_FILE"; then
  sed -i "s|^JWT_SECRET_KEY=.*|JWT_SECRET_KEY=${NEW_SECRET}|" "$ENV_FILE"
else
  printf '\nJWT_SECRET_KEY=%s\n' "$NEW_SECRET" >> "$ENV_FILE"
fi

echo "JWT_SECRET_KEY rotated in $ENV_FILE"
