#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Faxina — Relatório Semanal (segunda de manhã).
Lê o diário de eventos + recursos + tendência + ações das 2 VPS e monta um resumo:
o que aconteceu na semana, como estamos, análise preditiva, o que preocupa, o que reiniciar.
Envia no WhatsApp (notify.sh) e grava reports/weekly-latest.md. Use --dry p/ não enviar.
"""
import os, sys, json, time, subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(BASE, "config.json")))
NOW = int(time.time())
WEEK = 7 * 86400
DRY = "--dry" in sys.argv
VPS = [("main", None)]  # server-2 apagada em 09/09/2026
SEV_E = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

def sh(cmd, t=15):
    try: return subprocess.run(cmd, capture_output=True, text=True, timeout=t).stdout
    except Exception: return ""

def rd(remote, rel):
    if remote:
        return sh(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", remote,
                   "cat /root/loop-hunter/%s 2>/dev/null" % rel], 20)
    try: return open(os.path.join(BASE, rel)).read()
    except Exception: return ""

def jl(s):
    out = []
    for line in s.splitlines():
        line = line.strip()
        if line:
            try: out.append(json.loads(line))
            except Exception: pass
    return out

def restart_candidates(remote):
    # processos node/python destacados, antigos (>20d) e gordos (>800MB) — candidatos a reinício
    out = sh((["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", remote] if remote else ["bash", "-lc"])
             + ["ps -eo etimes,rss,comm,args --no-headers 2>/dev/null"], 15)
    res = []
    for line in out.splitlines():
        p = line.split(None, 3)
        if len(p) < 4: continue
        ets, rss, comm, args = p
        if not (ets.isdigit() and rss.isdigit()): continue
        if comm in ("node", "python", "python3", "next-server") and int(ets) > 20*86400 \
           and int(rss) > 800000 and "claude" not in args and "loop-hunter" not in args:
            res.append("%s (%dd, %dMB)" % (comm, int(ets)//86400, int(rss)//1024))
    return res[:5]

def main():
    end = time.strftime("%d/%m")
    start = time.strftime("%d/%m", time.localtime(NOW - WEEK))
    L = ["🗓️ *Faxina — Relatório Semanal*", "_%s a %s_" % (start, end), ""]

    all_open_sev = []     # achados abertos relevantes (as 2 VPS)
    week_appeared = 0; week_resolved = 0
    worst = "ok"

    L.append("*Como estamos:*")
    for label, remote in VPS:
        latest = json.loads(rd(remote, "reports/latest.json") or "{}")
        hw = latest.get("hardware") or {}
        finds = latest.get("findings", [])
        opensev = [f for f in finds if f.get("severity") in ("high", "critical", "medium")]
        dot = "🔴" if any(f["severity"] in ("high", "critical") for f in finds) else ("🟡" if any(f["severity"] == "medium" for f in finds) else "🟢")
        if dot == "🔴": worst = "alerta"
        elif dot == "🟡" and worst == "ok": worst = "atenção"
        load = (hw.get("load") or [0])[0]; cores = hw.get("cores", 1)
        mem = hw.get("mem", {}); disks = hw.get("disks", [])
        disk = next((d for d in disks if d["mount"] == "/"), disks[0] if disks else {})
        L.append("%s *%s* — CPU %d%% · RAM %d%% · disco %d%%" % (
            dot, label, round(load/cores*100) if cores else 0,
            round(mem.get("pct", 0)), disk.get("pct", 0)))
        for f in opensev:
            all_open_sev.append((label, f))

    # eventos da semana (as 2 VPS)
    notable = []
    for label, remote in VPS:
        evs = [e for e in jl(rd(remote, "state/events.jsonl")) if e.get("ts", 0) >= NOW - WEEK]
        week_appeared += sum(1 for e in evs if e.get("ev") == "apareceu")
        week_resolved += sum(1 for e in evs if e.get("ev") == "resolvido")
        for e in evs:
            if e.get("ev") == "apareceu" and e.get("severity") in ("high", "critical"):
                notable.append("%s %s · %s (%s)" % (SEV_E.get(e["severity"], ""), label, e.get("title", ""), e.get("code", "")))

    # ações da semana (audit do painel + act.sh)
    acts = 0
    for f in ("/root/loop-hunter-panel/actions.log", os.path.join(BASE, "logs/actions.log")):
        try:
            for line in open(f):
                if "[ACT]" in line or "[OK]" in line or "[CLEANUP]" in line:
                    acts += 1
        except Exception: pass

    L += ["", "*A semana que passou:*"]
    if week_appeared or week_resolved or acts:
        L.append("• %d problema(s) apareceram, %d resolvidos · %d ação(ões) de limpeza" % (week_appeared, week_resolved, acts))
        for n in notable[:5]:
            L.append("• " + n)
    else:
        L.append("• Semana tranquila — nada grave registrado. 👌")

    # análise preditiva
    L += ["", "*Análise preditiva:*"]
    pred_lines = []
    for label, remote in VPS:
        hist = [e for e in json.loads(rd(remote, "state/hw-history.json") or "[]") if isinstance(e, dict)]
        if len(hist) >= 3:
            span = (hist[-1]["ts"] - hist[0]["ts"]) / 86400.0
            if span >= 1:
                rate = (hist[-1]["du"] - hist[0]["du"]) / span
                free = hist[-1]["dt"] - hist[-1]["du"]
                if rate > 0.05:
                    days = int(free / rate)
                    pred_lines.append("• %s: disco enchendo ~%.1fGB/dia → cheio em ~%d dias" % (label, rate, days))
                elif rate < -0.05:
                    pred_lines.append("• %s: disco diminuindo (limpeza) — ok" % label)
                else:
                    pred_lines.append("• %s: disco estável 👍" % label)
        else:
            pred_lines.append("• %s: ainda juntando histórico (previsão em alguns dias)" % label)
    L += pred_lines

    # pra se preocupar
    L += ["", "*Pra se preocupar:*"]
    if all_open_sev:
        for label, f in sorted(all_open_sev, key=lambda x: x[1]["severity"] != "high")[:8]:
            L.append("%s %s · %s (%s)" % (SEV_E.get(f["severity"], ""), label, f.get("title", "")[:50], f.get("code", "")))
    else:
        L.append("• Nada aberto. 🟢")

    # pra reiniciar
    L += ["", "*Sugestões de reinício preventivo:*"]
    rc_any = False
    for label, remote in VPS:
        rc = restart_candidates(remote)
        for r in rc:
            L.append("• %s: %s — considere reiniciar em janela" % (label, r)); rc_any = True
    if not rc_any:
        L.append("• Nenhuma — nada pedindo reinício. 👍")

    # mudanças de config na semana (vault — main)
    L += ["", "*Mudanças de configuração (main):*"]
    try:
        out = sh(["git", "-C", "/root/.config-vault", "log", "--since", "7 days ago",
                  "--pretty=%ad %s", "--date=format:%d/%m %Hh"], 10)
        chg = [l for l in out.splitlines() if l.strip()]
        if chg:
            L.append("• %d alteração(ões) registrada(s) (com 'desfazer' disponível):" % len(chg))
            for l in chg[:5]:
                L.append("  – " + l)
        else:
            L.append("• Nenhuma mudança de config. 👍")
    except Exception:
        L.append("• (vault indisponível)")

    panel = CFG.get("panel_url", "")
    L += ["", "📊 Painel: %s" % panel, "Pra aprofundar qualquer item: digite o *código* (fxXXXX) ou *faxina* no Claude Code."]
    msg = "\n".join(L)

    try: open(os.path.join(BASE, "reports/weekly-latest.md"), "w").write(msg + "\n")
    except Exception: pass

    if DRY:
        print(msg)
    else:
        subprocess.run(["bash", os.path.join(BASE, "notify.sh"), msg], timeout=40)

if __name__ == "__main__":
    main()
