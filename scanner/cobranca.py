#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Faxina — COBRANÇA TEIMOSA (diária).

Motivo de existir (02/08/2026): a detecção nunca foi o problema. O certbot quebrou em
27/07 e a Faxina marcou vermelho no MESMO dia — mas o alerta toca uma vez, com cooldown
de 6h por fingerprint, e depois cala. Resultado: 6 dias parado até alguém digitar "faxina".

Esta rotina fecha o laço: todo dia ela olha o que está VERMELHO e ABERTO há mais de 48h
nas 2 VPS e cobra no Telegram, subindo o tom conforme envelhece. O achado só some da
cobrança quando o scanner PARA DE DETECTAR (resolvido de verdade) — não quando é lido.

Fonte da idade: state/open.json → campo "since" (gravado pelo hunt.py a cada scan).

Uso:  cobranca.py [--dry]      (--dry mostra a mensagem sem enviar)
Cron: 09:00 BRT na main (puxa a server-2 por ssh, igual ao weekly-report).
"""
import os, sys, json, time, subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
NOW = int(time.time())
DRY = "--dry" in sys.argv
VPS = [("main", None)]  # server-2 apagada em 09/09/2026
PAINEL = "http://guardian.example.com"

COBRAR_SEV = ("high", "critical")   # só vermelho incomoda todo dia
CARENCIA_H = 48                     # abaixo disso, o alerta normal do hunt.py já deu o recado

# Degraus de tom: (idade mínima em horas, emoji, recado de fechamento)
DEGRAUS = [
    (7 * 24, "🚨", "Tem item parado há mais de uma semana. Isso já não é fila, é esquecimento."),
    (3 * 24, "⚠️", "Tem item passando de 3 dias parado."),
    (CARENCIA_H, "⏰", "Achado vermelho passou de 48h sem resolução."),
]


def sh(cmd, t=20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=t).stdout
    except Exception:
        return ""


def rd(remote, rel):
    if remote:
        return sh(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", remote,
                   "cat /root/loop-hunter/%s 2>/dev/null" % rel], 25)
    try:
        return open(os.path.join(BASE, rel)).read()
    except Exception:
        return ""


def idade_humana(seg):
    d, h = seg // 86400, (seg % 86400) // 3600
    if d >= 1:
        return "%d dia%s" % (d, "s" if d > 1 else "") + (" e %dh" % h if h else "")
    return "%dh" % max(1, seg // 3600)


def degrau(seg):
    for horas, emoji, recado in DEGRAUS:
        if seg >= horas * 3600:
            return emoji, recado
    return DEGRAUS[-1][1:]   # não deveria chegar aqui (já filtrado por CARENCIA_H)


def coletar():
    """Devolve os achados vermelhos abertos há mais de CARENCIA_H, mais velhos primeiro."""
    itens = []
    for vps, remote in VPS:
        raw = rd(remote, "state/open.json")
        if not raw.strip():
            continue                      # VPS muda/inalcançável — o watchdog cuida disso
        try:
            aberto = json.loads(raw)
        except Exception:
            continue
        for fp, info in (aberto or {}).items():
            if info.get("severity") not in COBRAR_SEV:
                continue
            since = info.get("since")
            if not since:
                continue                  # achado anterior ao campo "since" — entra no próximo scan
            idade = NOW - int(since)
            if idade < CARENCIA_H * 3600:
                continue
            itens.append({"vps": vps, "idade": idade, "code": info.get("code", "?"),
                          "title": info.get("title", "(sem título)"),
                          "categoria": info.get("categoria") or ""})
    itens.sort(key=lambda x: -x["idade"])
    return itens


def montar(itens):
    n = len(itens)
    emoji_pior, recado = degrau(itens[0]["idade"])   # itens[0] = o mais velho manda no tom
    resumo = ("1 achado vermelho parado" if n == 1
              else "%d achados vermelhos parados" % n)
    linhas = ["%s FAXINA — cobrança" % emoji_pior, "%s nas suas VPS." % resumo, ""]
    for it in itens:
        emoji, _ = degrau(it["idade"])
        linhas.append("%s Parado há %s · %s" % (emoji, idade_humana(it["idade"]), it["vps"]))
        linhas.append("   %s" % it["title"])
        linhas.append("   → me manda o código: %s" % it["code"])
        linhas.append("")
    linhas.append(recado)
    linhas.append("Pra resolver: abra o Claude Code e digite o código do item.")
    linhas.append("Painel: %s" % PAINEL)
    return "\n".join(linhas)


def main():
    itens = coletar()
    if not itens:
        if DRY:
            print("(nada a cobrar — nenhum achado vermelho aberto há mais de %dh)" % CARENCIA_H)
        return 0                          # silêncio quando está tudo em dia: cobrança só quando cabe
    msg = montar(itens)
    if DRY:
        print(msg)
        return 0
    try:
        subprocess.run(["bash", os.path.join(BASE, "notify.sh"), msg], timeout=40)
    except Exception as e:
        sys.stderr.write("falha ao enviar cobranca: %s\n" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
