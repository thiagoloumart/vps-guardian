#!/bin/bash
# Caça-Loops — executor de AÇÕES SEGURAS (allowlist). Só faz operações não-destrutivas.
# Chamado pelo painel (local na main) ou via `ssh server-2 bash act.sh ...` (server-2).
# Uso:
#   act.sh reset_counter <arquivo.json> <keypath>   -> zera o contador (com backup)
#   act.sh rotate_log    <arquivo.log>              -> gzip backup + trunca no lugar
# Recusa qualquer outra ação, caminho fora das raízes permitidas, ou path traversal.
set -uo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
ACTION="${1:-}"; FILE="${2:-}"; KEY="${3:-}"
TS="$(date '+%Y%m%d-%H%M%S')"
AUDIT="$BASE/logs/actions.log"
mkdir -p "$BASE/logs"

fail(){ echo "ERRO: $1"; echo "$(date '+%F %T') [NEGADO] action=$ACTION file=$FILE key=$KEY motivo=$1" >> "$AUDIT"; exit 2; }

# --- validação de caminho ---
[ -n "$FILE" ] || fail "arquivo vazio"
case "$FILE" in
  *..*) fail "path traversal" ;;
  /root/*|/var/www/*|/var/log/*|/home/*) : ;;
  *) fail "caminho fora das raízes permitidas" ;;
esac
[ -f "$FILE" ] || fail "arquivo não existe"

case "$ACTION" in
  reset_counter)
    case "$FILE" in *.json) : ;; *) fail "reset_counter só em .json" ;; esac
    [ -n "$KEY" ] || fail "keypath vazio"
    cp -a "$FILE" "${FILE}.bak-${TS}" || fail "backup falhou"
    OLD=$(FILE="$FILE" KEY="$KEY" python3 - <<'PY'
import json,os,sys
f=os.environ['FILE']; key=os.environ['KEY'].strip('/').split('/')
d=json.load(open(f))
ref=d;
for k in key[:-1]: ref=ref[k]
old=ref.get(key[-1])
ref[key[-1]]=0
json.dump(d, open(f,'w'), indent=2)
print(old)
PY
) || fail "falha ao zerar contador"
    echo "OK: ${KEY} ${OLD} -> 0  (backup ${FILE}.bak-${TS})"
    echo "$(date '+%F %T') [OK] reset_counter file=$FILE key=$KEY old=$OLD" >> "$AUDIT"
    ;;
  rotate_log)
    SIZE=$(stat -c %s "$FILE" 2>/dev/null || echo 0)
    gzip -c "$FILE" > "${FILE}.${TS}.gz" || fail "gzip falhou"
    : > "$FILE" || fail "truncate falhou"   # trunca no lugar (preserva o inode p/ quem escreve)
    echo "OK: ${FILE} (${SIZE}B) -> backup ${FILE}.${TS}.gz e truncado"
    echo "$(date '+%F %T') [OK] rotate_log file=$FILE size=$SIZE" >> "$AUDIT"
    ;;
  *)
    fail "ação não permitida: '$ACTION'"
    ;;
esac
