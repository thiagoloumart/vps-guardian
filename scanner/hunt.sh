#!/bin/bash
# Caça-Loops — wrapper de segurança. Garante: um único scan por vez (flock),
# baixa prioridade (nice/ionice), e teto de tempo (timeout) pra NUNCA virar
# um loop/consumidor ele mesmo. Detecção = leitura local, zero request externo.
set -uo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:---leve}"
LOCK="/tmp/loop-hunter.lock"
LOG="$BASE/logs/hunt.log"
mkdir -p "$BASE/logs"

exec 9>"$LOCK"
if ! flock -n 9; then
  echo "$(date '+%F %T') [skip] scan anterior ainda rodando" >> "$LOG"
  exit 0
fi

NICE="nice -n 15"
command -v ionice >/dev/null 2>&1 && NICE="ionice -c3 $NICE"

{
  echo "----- $(date '+%F %T') mode=$MODE -----"
  timeout 115 $NICE python3 "$BASE/hunt.py" "$MODE"
  echo "exit=$?"
} >> "$LOG" 2>&1
