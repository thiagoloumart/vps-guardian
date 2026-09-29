#!/bin/bash
# Faxina — "Botão de desfazer": snapshot versionado (git) das configs mutáveis críticas.
# Toda mudança vira reversível e visível (git log/diff). SEM SEGREDOS: redação + exclusões
# + pm2 sanitizado. Roda: diário (cron), sob demanda, e antes de mudanças que a gente faz.
set -uo pipefail
REPO="/root/.config-vault"          # FORA de loop-hunter (não vai no rsync p/ server-2)
TRIG="${1:-manual}"
mkdir -p "$REPO"
cd "$REPO" || exit 1
if [ ! -d .git ]; then
  git init -q
  git config user.email "guardian@localhost"
  git config user.name "Faxina"
  printf "config-vault — snapshots versionados das configs (SEM segredos).\nDesfazer: git log / git show / copiar o arquivo de volta + recarregar o serviço.\n" > README.txt
fi

# redação de segredos em qualquer texto
redact(){ sed -E 's/((api[_-]?key|token|password|passwd|secret|bearer|authorization)["'"'"' ]*[:=] *)[^ "'"'"',;]+/\1[REDACTED]/Ig'; }

# limpa o conteúdo rastreado (pra capturar deleções), preserva .git e README
find . -mindepth 1 -maxdepth 1 ! -name .git ! -name README.txt -exec rm -rf {} + 2>/dev/null
mkdir -p nginx crontabs/cron.d systemd etc pm2 docker

# nginx (exclui chaves/htpasswd — *htpasswd* pega .htpasswd-foo também)
rsync -a --exclude '*htpasswd*' --exclude '*.key' --exclude '*.pem' --exclude '*.crt' /etc/nginx/ nginx/ 2>/dev/null

# crontabs de todos os usuários (redigidos)
for u in $(cut -d: -f1 /etc/passwd); do
  c=$(crontab -l -u "$u" 2>/dev/null) && [ -n "$c" ] && printf '%s\n' "$c" | redact > "crontabs/$u.cron"
done
[ -f /etc/crontab ] && redact < /etc/crontab > etc/crontab
for f in /etc/cron.d/*; do [ -f "$f" ] && redact < "$f" > "crontabs/cron.d/$(basename "$f")"; done 2>/dev/null

# systemd units custom (redige Environment=)
for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
  [ -f "$f" ] && redact < "$f" > "systemd/$(basename "$f")"
done 2>/dev/null
systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' > systemd/_enabled.txt

# etc chave (redigidos)
for f in /etc/hosts /etc/fstab /etc/ssh/sshd_config; do
  [ -f "$f" ] && redact < "$f" > "etc/$(basename "$f")"
done

# pm2 SANITIZADO (sem env/segredos)
if command -v pm2 >/dev/null; then
  pm2 jlist 2>/dev/null | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
e=lambda p:p.get('pm2_env',{})
out=[{'name':p.get('name'),'script':e(p).get('pm_exec_path'),'cwd':e(p).get('pm_cwd'),
      'args':e(p).get('args'),'instances':e(p).get('instances'),'mode':e(p).get('exec_mode'),
      'autorestart':e(p).get('autorestart')} for p in d]
json.dump(sorted(out,key=lambda x:str(x['name'])), open('pm2/processes.json','w'), indent=2, ensure_ascii=False)
" 2>/dev/null
fi

# docker inventário (só nomes/imagem/status)
if command -v docker >/dev/null; then
  docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null | sort > docker/containers.txt
  docker service ls --format '{{.Name}}\t{{.Replicas}}\t{{.Image}}' 2>/dev/null | sort > docker/services.txt
fi

# ---- VARREDURA DE SEGURANÇA (belt & suspenders) ----
# 1) remove qualquer material sensível que tenha escapado
find . -path ./.git -prune -o -type f \( -iname '*htpasswd*' -o -iname '*.key' -o -iname '*.pem' \
  -o -iname '*.crt' -o -iname 'id_*' -o -iname '*.env' -o -iname '*.pfx' -o -iname 'shadow' \) \
  -exec rm -f {} + 2>/dev/null
# 2) redige segredos inline em TODOS os textos restantes
while IFS= read -r f; do
  redact < "$f" > "$f.__t" 2>/dev/null && mv "$f.__t" "$f"
done < <(find . -path ./.git -prune -o -type f -print)

git add -A
if git diff --cached --quiet 2>/dev/null; then
  echo "$(date '+%F %T') sem mudanças ($TRIG)"
else
  git commit -q -m "snapshot $(date '+%F %H:%M') [$TRIG]"
  echo "$(date '+%F %T') commit feito ($TRIG): $(git diff --name-only HEAD~1 HEAD 2>/dev/null | wc -l) arquivo(s)"
fi
