#!/bin/bash
# Caça-Loops — instala/atualiza as linhas de cron de forma idempotente.
# Leve a cada 15 min + profundo 1x/dia (06:40). Remove linhas antigas antes de re-add.
set -euo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
LEVE="*/15 * * * * $BASE/hunt.sh --leve"
PROF="40 6 * * * $BASE/hunt.sh --profundo"
TAG="# Caça-Loops (caçador de loops/desperdício)"

TMP="$(mktemp)"
crontab -l 2>/dev/null | grep -v "loop-hunter/hunt.sh" | grep -vF "$TAG" > "$TMP" || true
{
  echo "$TAG"
  echo "$LEVE"
  echo "$PROF"
} >> "$TMP"
crontab "$TMP"
rm -f "$TMP"
echo "Cron instalado:"
crontab -l | grep -A2 "Caça-Loops"
