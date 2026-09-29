#!/bin/bash
# Faxina — "Quem vigia o vigia". Roda via systemd timer (INDEPENDENTE do cron — sobrevive até
# se o cron morrer) e checa se o próprio Faxina parou de escanear (main/server-2) ou se o canal
# principal (primary) caiu. Avisa pelo canal RESERVA quando preciso. Cooldown p/ não repetir.
set -uo pipefail
BASE="/root/loop-hunter"
STATE="$BASE/state/watchdog.json"
LOG="$BASE/logs/watchdog.log"
CFG="$BASE/config.json"
# credenciais lidas do config.json (não hardcoded — nada de segredo no script)
read -r API KEY INST < <(python3 -c "
import json
c=json.load(open('$CFG'))['channel']
print(c['api'].rsplit('/message',1)[0], c['apikey'], c['instance'])
")
KEY="apikey: $KEY"
STALE_MIN=40          # 2+ ciclos do scan leve (15min) de tolerância
COOLDOWN=10800        # 3h entre repetições do mesmo alerta
NOW=$(date +%s)
DRY="${1:-}"
mkdir -p "$BASE/logs" "$BASE/state"
log(){ echo "$(date '+%F %T') $*" >> "$LOG"; }

get_last(){ python3 -c "import json
try: print(json.load(open('$STATE')).get('$1',0))
except: print(0)" 2>/dev/null; }
set_last(){ python3 -c "import json
try: d=json.load(open('$STATE'))
except: d={}
d['$1']=$NOW; json.dump(d, open('$STATE','w'))" 2>/dev/null; }

primary_state(){ curl -s --max-time 10 "$API/instance/connectionState/$INST" -H "$KEY" 2>/dev/null \
  | python3 -c "import json,sys
try: print(json.load(sys.stdin)['instance']['state'])
except: print('unknown')" 2>/dev/null; }

send(){ # $1=msg — envio delegado ao notify.sh (Telegram e, se falhar, WhatsApp)
  local MSG="$1"
  if [ "$DRY" = "--dry" ]; then echo "=== DRY ===" ; echo "$MSG"; echo "==="; return 0; fi
  if bash "$BASE/notify.sh" "$MSG"; then log "enviado (notify.sh)"; else log "FALHA em todos os canais"; fi
}

maybe(){ # $1=chave $2=msg $3=primary_ok
  local last; last=$(get_last "$1")
  if [ "$DRY" = "--dry" ] || [ $(( NOW - last )) -ge $COOLDOWN ]; then
    send "$2" "$3"; [ "$DRY" = "--dry" ] || set_last "$1"
  else
    log "suprimido (cooldown) $1"
  fi
}

BSTATE=$(primary_state); BOK=1; [ "$BSTATE" = "open" ] || BOK=0

# 1) main escaneou recentemente?
M_AGE=$(( (NOW - $(stat -c %Y "$BASE/reports/latest.json" 2>/dev/null || echo 0)) / 60 ))
if [ "$M_AGE" -gt "$STALE_MIN" ]; then
  maybe "main_stale" "🛡️ *Faxina ALERTA* — o monitor PAROU de escanear na *main* (último scan há ${M_AGE} min). Provável hunt.py quebrado ou cron parado. As checagens/alertas estão CEGOS até consertar — digite *faxina* no Claude Code." "$BOK"
fi

# 2) [29/09/2026] checagem da server-2 removida — servidor apagado em 09/09.

# 3) primary caído? (avisa pelo reserva)
if [ "$BOK" = "0" ]; then
  maybe "primary_down" "🛡️ *Faxina ALERTA* — a instância *${INST}* do WhatsApp está fora (state=${BSTATE}). Os alertas seguem chegando pelo Telegram; o que está parado é o WhatsApp (áudios do Cérebro / captura do Radar). Digite *faxina* no Claude Code pra religar." "$BOK"
fi

log "ok M_AGE=${M_AGE}min primary=${BSTATE}"
