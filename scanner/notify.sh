#!/bin/bash
# Faxina/Caça-Loops — ÚNICA parte que toca a rede.
# Canal 1: TELEGRAM (oficial desde 15/07/2026) — token/chat em $TGCONF, fora do repo.
# Canal 2 (reserva): WhatsApp via Evolution API, com um prefixo configurável na frente
# para o destinatário saber de onde veio o alerta.
# Falha silenciosa, nunca loopa.
set -uo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
CFG="$BASE/config.json"
MSG="${1:-$(cat)}"
LOG="$BASE/logs/notify.log"
STAMP="$(date '+%F %T')"

read -r API NUM KEY INST FB TGCONF < <(python3 -c "
import json
c=json.load(open('$CFG'))['channel']
print(c['api'], c['number'], c['apikey'], c['instance'], c.get('fallback_instance','') or '-', c.get('telegram_conf','-'))
")

# --- Canal 1: Telegram ---
TG_CODE="sem-conf"
if [ "$TGCONF" != "-" ] && [ -r "$TGCONF" ]; then
  TG_TOKEN="$(grep -oP '^TELEGRAM_BOT_TOKEN=\K\S+' "$TGCONF" 2>/dev/null)"
  TG_CHAT="$(grep -oP '^TELEGRAM_CHAT_ID=\K\S+' "$TGCONF" 2>/dev/null)"
  if [ -n "${TG_TOKEN:-}" ] && [ -n "${TG_CHAT:-}" ]; then
    TG_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
      "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
      --data-urlencode "chat_id=${TG_CHAT}" --data-urlencode "text=${MSG}" 2>/dev/null)
  else
    TG_CODE="sem-token"
  fi
fi

if [ "$TG_CODE" = "200" ]; then
  echo "[notify] telegram=200 $STAMP" >> "$LOG"
  exit 0
fi

# --- Canal 2 (reserva): WhatsApp ---
WMSG="*[VPS Guardian]*
$MSG"
PAYLOAD=$(printf '%s' "$WMSG" | jq -Rs --arg n "$NUM" '{number:$n, text:.}' 2>/dev/null) || {
  # fallback sem jq (server-2 não tem jq)
  PAYLOAD=$(MSG="$WMSG" NUM="$NUM" python3 -c "import json,os; print(json.dumps({'number':os.environ['NUM'],'text':os.environ['MSG']}))")
}

post(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$API/$1" \
  -H "apikey: $KEY" -H "Content-Type: application/json" -d "$PAYLOAD" --max-time 15 2>/dev/null; }

CODE=$(post "$INST")
if [ "$CODE" != "201" ] && [ "$CODE" != "200" ] && [ "$FB" != "-" ]; then
  CODE2=$(post "$FB")
  echo "[notify] telegram=$TG_CODE FALHOU -> wa $INST=$CODE -> reserva $FB=$CODE2 $STAMP" >> "$LOG"
  [ "$CODE2" = "201" ] || [ "$CODE2" = "200" ]
else
  echo "[notify] telegram=$TG_CODE FALHOU -> wa $INST=$CODE $STAMP" >> "$LOG"
  [ "$CODE" = "201" ] || [ "$CODE" = "200" ]
fi
