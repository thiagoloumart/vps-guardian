#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Caça-Loops — caçador periódico de loops / desperdícios de recurso nas VPS.

PRINCÍPIO: a DETECÇÃO é 100% leitura local (ps, /proc, crontab, systemctl,
pm2 jlist, ss, stat/seek em logs). NENHUMA requisição externa aqui. Só o
notify.sh (chamado quando há alerta de severidade alta) toca a rede.

Modos:  --leve     (rápido, a cada 15 min)   --profundo (1x/dia, + sockets/logs antigos)
Saída:  reports/latest.md  +  reports/AAAA-MM-DD.md  +  JSON no stdout.
Alerta: só severidade high/critical, com cooldown por fingerprint (anti-spam).
"""
import os, sys, json, time, re, glob, subprocess, signal, socket, hashlib, fnmatch

BASE = os.path.dirname(os.path.abspath(__file__))
CFG  = json.load(open(os.path.join(BASE, "config.json")))
STATE_DIR = os.path.join(BASE, "state")
REPORT_DIR = os.path.join(BASE, "reports")
SNAP_FILE = os.path.join(STATE_DIR, "snapshot.json")
FIND_FILE = os.path.join(STATE_DIR, "findings.json")
CLK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

MODE = "profundo" if "--profundo" in sys.argv else "leve"
NOW  = int(time.time())
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---- guarda de segurança: nunca rodar mais que 110s (não virar loop ele mesmo) ----
def _timeout(*_):
    sys.stderr.write("hunt.py: timeout de seguranca atingido\n"); sys.exit(0)
try:
    signal.signal(signal.SIGALRM, _timeout); signal.alarm(110)
except Exception:
    pass

def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""

def load_json(path, default):
    try:
        return json.load(open(path))
    except Exception:
        return default

def vps_name():
    n = CFG.get("vps_name", "AUTO")
    if n and n != "AUTO":
        return n
    try:
        return socket.gethostname()
    except Exception:
        return "vps"

# =========================================================================
# Coletores (cada um best-effort; falha isolada não derruba o scan)
# =========================================================================

def collect_processes():
    """ps + leitura de /proc para CPU acumulada (delta entre scans = CPU real do intervalo)."""
    procs = {}
    try:
        UP = float(open("/proc/uptime").read().split()[0])
    except Exception:
        UP = 0
    out = run(["ps", "-eo", "pid,ppid,user,rss,comm,args", "--no-headers"], 20)
    for line in out.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        pid, ppid, user, rss, comm, args = parts
        if not pid.isdigit():
            continue
        pid = int(pid)
        ut = st = starttime = 0
        try:
            with open("/proc/%d/stat" % pid) as f:
                fields = f.read().rsplit(")", 1)[1].split()
            # após "comm)": índices deslocados; utime=fields[11], stime=fields[12], starttime=fields[19]
            ut = int(fields[11]); st = int(fields[12]); starttime = int(fields[19])
        except Exception:
            pass
        elapsed = int(UP - starttime / CLK) if (UP and starttime) else 0
        procs[pid] = {
            "pid": pid, "ppid": int(ppid) if ppid.isdigit() else 0,
            "user": user, "rss_kb": int(rss) if rss.isdigit() else 0,
            "comm": comm, "args": args[:300],
            "cpu_ticks": ut + st, "starttime": starttime, "elapsed": max(0, elapsed),
        }
    return procs

def normalize_sig(p):
    """Assinatura p/ detectar processos duplicados/competindo."""
    comm = p["comm"]
    toks = p["args"].split()
    script = ""
    for t in toks[1:]:
        if "/" in t and not t.startswith("-"):
            script = os.path.basename(t); break
        if t.endswith((".js", ".py", ".sh", ".mjs", ".ts")):
            script = os.path.basename(t); break
    return "%s|%s" % (comm, script) if script else comm

def collect_pm2():
    if not which("pm2"):
        return []
    out = run(["pm2", "jlist"], 20)
    try:
        data = json.loads(out)
    except Exception:
        return []
    res = []
    for p in data:
        env = p.get("pm2_env", {})
        res.append({
            "name": p.get("name"), "pid": p.get("pid"),
            "status": env.get("status"),
            "restarts": env.get("restart_time", 0),
            "unstable": env.get("unstable_restarts", 0),
        })
    return res

def which(b):
    return run(["bash", "-lc", "command -v %s 2>/dev/null" % b], 5).strip()

def collect_systemd():
    """NRestarts de serviços custom em execução (vendor filtrado)."""
    res = []
    out = run(["systemctl", "list-units", "--type=service", "--state=running",
               "--no-legend", "--plain"], 15)
    vendor = re.compile(r"^(systemd|dbus|ssh|cron|networkd|resolved|user@|getty|"
                        r"rsyslog|polkit|accounts|unattended|snapd|multipathd|"
                        r"udisks|modemmanager|serial-getty|qemu|atd|containerd|"
                        r"docker|postgresql|nginx|fail2ban|tailscaled)")
    units = []
    for line in out.splitlines():
        u = line.split()
        if not u:
            continue
        name = u[0]
        if name.endswith(".service") and not vendor.match(name):
            units.append(name)
    units = units[:40]
    if not units:
        return res
    show = run(["systemctl", "show", "-p", "Id", "-p", "NRestarts"] + units, 20)
    cur = {}
    for blk in show.split("\n\n"):
        d = {}
        for ln in blk.splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1); d[k] = v
        if d.get("Id"):
            try:
                res.append({"unit": d["Id"], "nrestarts": int(d.get("NRestarts", "0") or 0)})
            except Exception:
                pass
    # fallback: systemctl show com múltiplas units às vezes não separa por \n\n
    if not res:
        for u in units:
            s = run(["systemctl", "show", "-p", "NRestarts", "--value", u], 8).strip()
            if s.isdigit():
                res.append({"unit": u, "nrestarts": int(s)})
    return res

def collect_crontabs():
    """Mapa comando->schedule de todos os usuários + flags de alta frequência."""
    jobs = []
    users = run(["bash", "-lc", "cut -d: -f1 /etc/passwd"], 5).split()
    for u in users:
        out = run(["crontab", "-l", "-u", u], 6)
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$", line)
            if not m:
                continue
            minute, cmd = m.group(1), m.group(6)
            freq_min = None
            if minute == "*":
                freq_min = 1
            else:
                mm = re.match(r"\*/(\d+)", minute)
                if mm:
                    freq_min = int(mm.group(1))
            jobs.append({"user": u, "schedule": " ".join(m.group(1, 2, 3, 4, 5)),
                         "freq_min": freq_min, "cmd": cmd})
    return jobs

def cron_for_path(jobs, needle):
    for j in jobs:
        if needle and needle in j["cmd"]:
            return j
    return None

def collect_logs(prev_logs, deep=False):
    """Lê APENAS os bytes novos de cada log desde o último scan; mede churn + erros."""
    pats = re.compile("|".join("(%s)" % p for p in CFG["error_patterns"]), re.IGNORECASE)
    excl = CFG.get("log_exclude_substr", [])
    cap  = CFG.get("max_log_slice_bytes", 2 << 20)
    files = []
    for g in CFG["log_globs"]:
        files += glob.glob(g, recursive=True)
    files = [f for f in set(files) if not any(x in f for x in excl)]
    # leve: só arquivos tocados recentemente; profundo: todos
    horizon = NOW - (3600 if not deep else 8 * 3600)
    cand = []
    for f in files:
        try:
            stt = os.stat(f)
        except Exception:
            continue
        if not deep and stt.st_mtime < horizon:
            new_logs_passthrough(prev_logs, f, stt.st_size)
            continue
        cand.append((f, stt))
    cand.sort(key=lambda x: x[1].st_mtime, reverse=True)
    cand = cand[: CFG.get("max_log_files", 250)]
    results, new_state = [], {}
    for f, stt in cand:
        size = stt.st_size
        seen_before = f in prev_logs           # cold-start / arquivo novo: só linha de base
        prev = prev_logs.get(f, {}).get("size", 0)
        if prev > size:                         # rotacionou/truncou
            prev = 0
        appended = size - prev
        new_state[f] = {"size": size, "mtime": int(stt.st_mtime)}
        if not seen_before or appended <= 0:
            continue                            # nada a medir ainda
        err = 0
        try:
            with open(f, "rb") as fh:
                fh.seek(prev)
                data = fh.read(min(appended, cap)).decode("utf-8", "replace")
            err = len(pats.findall(data))
        except Exception:
            pass
        results.append({"file": f, "appended": appended, "err_lines": err})
    # preserva tamanho dos que não recheckamos (passthrough já fez)
    for f, v in prev_logs.items():
        new_state.setdefault(f, v)
    return results, new_state

def new_logs_passthrough(prev_logs, f, size):
    pass  # placeholder: estado preservado no merge final

def collect_counters():
    """Procura contadores de falha consecutiva inflados em arquivos de estado JSON."""
    keys = CFG["counter_keys"]
    hits = []
    files = []
    for g in CFG["counter_state_globs"]:
        files += glob.glob(g)
    for f in list(set(files))[:120]:
        try:
            if os.path.getsize(f) > 1_000_000:
                continue
            d = json.load(open(f))
        except Exception:
            continue
        def walk(o, path=""):
            if isinstance(o, dict):
                for k, v in o.items():
                    walk(v, path + "/" + str(k))
            elif isinstance(o, (int, float)) and not isinstance(o, bool):
                kl = path.lower()
                if any(ck in kl for ck in keys) and o >= CFG["thresholds"]["counter_value"]:
                    hits.append({"file": f, "key": path.lstrip("/"), "value": o})
        walk(d)
    return hits

def collect_disk():
    out = run(["df", "-P", "-x", "tmpfs", "-x", "devtmpfs"], 10)
    res = []
    for line in out.splitlines()[1:]:
        c = line.split()
        if len(c) >= 6 and c[4].endswith("%"):
            try:
                pct = int(c[4][:-1])
            except Exception:
                continue
            if pct >= CFG["thresholds"]["disk_pct"]:
                res.append({"mount": c[5], "pct": pct})
    return res

def ip_class(ip):
    ip = ip.strip("[]")
    if ip.startswith("127.") or ip == "::1" or ip == "0.0.0.0" or ip == "*":
        return "loopback"
    if ip.startswith(("10.", "192.168.")):
        return "private"
    if ip.startswith("172."):
        try:
            return "private" if 16 <= int(ip.split(".")[1]) <= 31 else "public"
        except Exception:
            return "public"
    if ip.startswith("100."):                 # CGNAT / Tailscale (100.64–100.127)
        try:
            return "private" if 64 <= int(ip.split(".")[1]) <= 127 else "public"
        except Exception:
            return "public"
    if ip.startswith(("fe80", "fc", "fd", "::")):
        return "private"
    return "public"

def collect_sockets():
    """profundo: conexões established por remoto EXTERNO. Muitas p/ 1 remoto = storm em voo.
    Ignora: loopback (tráfego interno normal) e conexões de sessões `claude` (tráfego legítimo
    pra API da Anthropic — senão 6 sessões viram 'storm' falso)."""
    out = run(["ss", "-tnpH", "state", "established"], 12)
    counts = {}  # remote -> [count, cls, set(pids)]
    for line in out.splitlines():
        c = line.split()
        if len(c) < 4:
            continue
        remote = c[3].rsplit(":", 1)[0]
        cls = ip_class(remote)
        if cls == "loopback":
            continue
        mp = re.search(r'"([^"]+)",pid=(\d+)', line)
        comm = mp.group(1) if mp else ""
        if comm.startswith("claude"):       # tráfego claude↔Anthropic é esperado
            continue
        rec = counts.setdefault(remote, [0, cls, set()])
        rec[0] += 1
        if mp:
            rec[2].add(mp.group(2))
    th = CFG["thresholds"]["conn_same_remote"]
    res = []
    for r, (n, cls, pids) in counts.items():
        if (cls == "public" and n >= th) or (cls == "private" and n >= th * 2):
            res.append({"remote": r, "conns": n, "cls": cls, "pids": sorted(pids)})
    return res

def collect_listen_ports():
    out = run(["ss", "-lntpH"], 10)
    by_pid = {}
    for line in out.splitlines():
        m = re.search(r"pid=(\d+)", line)
        c = line.split()
        if m and len(c) >= 4:
            by_pid.setdefault(m.group(1), []).append(c[3].rsplit(":", 1)[-1])
    return by_pid

# =========================================================================
# Avaliação de risco de matar  ("matá-lo traz risco a alguma operação?")
# =========================================================================
def kill_risk(pid, procs, listen_by_pid, cron_jobs, pm2_pids, children):
    p = procs.get(pid)
    if not p:
        return ("desconhecido", "Processo já não existe.")
    comm = p["comm"]
    if comm in CFG["kill_critical_whitelist"]:
        return ("NÃO MATAR", "Serviço crítico de base (%s). Matar quebra produção." % comm)
    if str(pid) in pm2_pids:
        return ("matar é inútil", "Gerenciado por pm2 — vai renascer. Ação certa: `pm2 stop <app>`.")
    ports = listen_by_pid.get(str(pid))
    if ports:
        return ("ARRISCADO", "Atende porta(s) %s — algo depende dele. Verificar antes." % ",".join(sorted(set(ports))))
    kids = children.get(pid, [])
    if kids:
        return ("atenção", "Tem %d processo(s) filho(s) — pode derrubar dependências." % len(kids))
    cj = cron_for_path(cron_jobs, os.path.basename(p["args"].split()[0]) if p["args"] else "")
    if cj:
        return ("transitório", "Disparado por cron (%s). Matar resolve só agora; ação certa: editar/desligar a linha do cron." % cj["schedule"])
    return ("provavelmente seguro", "Sem porta, sem filhos, fora de pm2/cron óbvio. Confirmar antes de matar.")

def collect_exposure():
    """Raio-X de exposição: o que está REALMENTE aberto pra internet (bind 0.0.0.0 E liberado no
    ufw) + postura (ufw/fail2ban/SSH). Cruza com o firewall p/ não gritar por bind protegido."""
    data = {"exposed": [], "ufw": "n/a", "fail2ban": "?", "ssh": {}}
    ufw_out = run(["bash", "-lc", "ufw status 2>/dev/null"], 8)
    low = ufw_out.lower()
    data["ufw"] = "active" if "status: active" in low else ("inactive" if "status: inactive" in low else "n/a")
    allowed = set()
    for line in ufw_out.splitlines():
        if "ALLOW" in line and "Anywhere" in line and not any(x in line for x in ("100.", "127.", "192.168", "10.", "(v6)")):
            m = re.match(r"^\s*(\d+)", line)
            if m: allowed.add(int(m.group(1)))
    # mapa docker porta->container (p/ nomear)
    dports = {}
    for line in run(["bash", "-lc", "docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null"], 10).splitlines():
        pr = line.split("|")
        if len(pr) >= 2:
            for m in re.finditer(r"0\.0\.0\.0:(\d+)->", pr[1]):
                dports[int(m.group(1))] = pr[0]
    SENS = {5432, 5544, 3306, 6379, 6390, 27017, 9200, 5984, 11211, 5672, 9000, 15672}
    seen = set()
    for line in run(["ss", "-lntpH"], 10).splitlines():
        c = line.split()
        if len(c) < 4: continue
        local = c[3]
        if not (local.startswith("0.0.0.0:") or local.startswith("[::]:") or local.startswith("*:")):
            continue
        try: port = int(local.rsplit(":", 1)[1])
        except Exception: continue
        if port in seen or port not in allowed or port in (22, 80, 443):
            continue
        seen.add(port)
        mp = re.search(r'"([^"]+)"', line); comm = mp.group(1) if mp else "?"
        name = "%s (docker)" % dports[port] if (comm == "docker-proxy" and port in dports) else comm
        sens = port in SENS or any(s in name.lower() for s in ("postgres", "redis", "mongo", "mysql", "maria", "elastic", "memcache"))
        data["exposed"].append({"port": port, "proc": name, "sensitive": sens})
    data["fail2ban"] = run(["systemctl", "is-active", "fail2ban"], 6).strip() or "?"
    sc = run(["bash", "-lc", "grep -iE '^PermitRootLogin|^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null"], 6)
    data["ssh"]["root"] = "yes" if re.search(r"permitrootlogin\s+yes", sc, re.I) else "ok"
    data["ssh"]["passwd"] = "yes" if re.search(r"passwordauthentication\s+yes", sc, re.I) else "ok"
    return data

def collect_inventory():
    """Mapa da casa: inventário vivo de pm2/docker/systemd/crons/portas/subdomínios. Read-only."""
    inv = {}
    pm2 = []
    if which("pm2"):
        try:
            for p in json.loads(run(["pm2", "jlist"], 15)):
                e = p.get("pm2_env", {})
                up = (NOW * 1000 - e.get("pm_uptime", NOW * 1000)) / 3600000.0
                pm2.append({"name": p.get("name"), "status": e.get("status"),
                            "restarts": e.get("restart_time"),
                            "uptime_h": round(up, 1) if e.get("status") == "online" else 0,
                            "script": os.path.basename(e.get("pm_exec_path", "") or "")})
        except Exception:
            pass
    inv["pm2"] = sorted(pm2, key=lambda x: str(x.get("name")))
    dock = {"containers": [], "services": []}
    if which("docker"):
        for line in run(["bash", "-lc", "docker ps -a --format '{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null"], 10).splitlines():
            pr = line.split("|")
            if len(pr) >= 3:
                dock["containers"].append({"name": pr[0], "status": pr[1], "image": pr[2]})
        for line in run(["bash", "-lc", "docker service ls --format '{{.Name}}|{{.Replicas}}|{{.Image}}' 2>/dev/null"], 10).splitlines():
            pr = line.split("|")
            if len(pr) >= 2:
                dock["services"].append({"name": pr[0], "replicas": pr[1], "image": pr[2] if len(pr) > 2 else ""})
    inv["docker"] = dock
    vendor = re.compile(r"^(systemd|dbus|ssh|cron|networkd|resolved|user@|getty|rsyslog|polkit|"
                        r"accounts|unattended|snapd|multipathd|udisks|modemmanager|serial-getty|"
                        r"qemu|atd|containerd|docker|postgresql|nginx|fail2ban|tailscaled)")
    units = []
    for line in run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"], 12).splitlines():
        u = line.split()
        if u and u[0].endswith(".service") and not vendor.match(u[0]):
            units.append(u[0])
    inv["systemd"] = units[:40]
    crons = []
    for usr in run(["bash", "-lc", "cut -d: -f1 /etc/passwd"], 5).split():
        for line in run(["crontab", "-l", "-u", usr], 6).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                m = re.match(r"^(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.*)$", line)
                if m:
                    crons.append({"user": usr, "sched": m.group(1), "cmd": m.group(2)[:90]})
    inv["crons"] = crons
    ports = {}
    for line in run(["ss", "-lntpH"], 10).splitlines():
        c = line.split()
        if len(c) < 4:
            continue
        addr = c[3]
        try: port = int(addr.rsplit(":", 1)[1])
        except Exception: continue
        host = addr.rsplit(":", 1)[0]
        cls = "loopback" if host.startswith(("127.", "[::1")) else ("tailscale" if host.startswith("100.") else "público")
        mp = re.search(r'"([^"]+)"', line)
        # 'público' vence se a porta aparecer em mais de um bind
        if port not in ports or cls == "público":
            ports[port] = {"port": port, "cls": cls, "proc": mp.group(1) if mp else "?"}
    inv["ports"] = [ports[k] for k in sorted(ports)]
    listening = set(ports.keys())
    subs = {}
    names, proxy = [], None
    def flush():
        for n in names:
            if "." in n and not n.startswith("*"):
                st = "estático/outro" if proxy is None else ("ok" if proxy in listening else "⚠️ backend morto")
                subs[n] = {"name": n, "backend": proxy, "status": st}
    for line in run(["bash", "-lc", "nginx -T 2>/dev/null"], 15).splitlines():
        s = line.strip()
        if s.startswith("server_name"):
            flush(); names = [x for x in s.replace(";", "").split()[1:]]; proxy = None
        else:
            m = re.search(r"proxy_pass\s+https?://(?:127\.0\.0\.1|localhost):(\d+)", s)
            if m: proxy = int(m.group(1))
    flush()
    inv["subdomains"] = sorted(subs.values(), key=lambda x: x["name"])
    return inv

def collect_hardware():
    """Snapshot de recursos: CPU(load/cores), RAM, swap, discos, uptime. Tudo leitura local."""
    hw = {"cores": os.cpu_count() or 1}
    try:
        hw["load"] = [round(float(x), 2) for x in open("/proc/loadavg").read().split()[:3]]
    except Exception:
        hw["load"] = [0, 0, 0]
    try:
        mi = {}
        for line in open("/proc/meminfo"):
            pp = line.split(":")
            if len(pp) == 2:
                mi[pp[0]] = int(pp[1].strip().split()[0])
        tot = mi.get("MemTotal", 0); av = mi.get("MemAvailable", mi.get("MemFree", 0))
        hw["mem"] = {"total_mb": tot // 1024, "avail_mb": av // 1024, "used_mb": (tot - av) // 1024,
                     "pct": round((tot - av) * 100 / tot, 1) if tot else 0}
        swt = mi.get("SwapTotal", 0); swf = mi.get("SwapFree", 0)
        hw["swap"] = {"total_mb": swt // 1024, "used_mb": (swt - swf) // 1024,
                      "pct": round((swt - swf) * 100 / swt, 1) if swt else 0}
    except Exception:
        pass
    disks = []
    try:
        for line in run(["df", "-PB1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay", "-x", "squashfs"], 10).splitlines()[1:]:
            c = line.split()
            if len(c) >= 6 and c[4].endswith("%") and not c[5].startswith(("/snap", "/boot/efi")):
                disks.append({"mount": c[5], "total_gb": round(int(c[1]) / 1e9, 1),
                              "used_gb": round(int(c[2]) / 1e9, 1), "pct": int(c[4][:-1])})
    except Exception:
        pass
    hw["disks"] = disks
    try:
        hw["uptime_h"] = round(float(open("/proc/uptime").read().split()[0]) / 3600, 1)
    except Exception:
        hw["uptime_h"] = 0
    return hw

# =========================================================================
# Análise → findings
# =========================================================================
def analyze():
    snap = load_json(SNAP_FILE, {})
    prev_procs = snap.get("procs", {})
    prev_pm2   = snap.get("pm2", {})
    prev_logs  = snap.get("logs", {})
    prev_wall  = snap.get("ts", NOW - 900)
    wall = max(1, NOW - prev_wall)

    procs = collect_processes()
    pm2   = collect_pm2()
    sysd  = collect_systemd()
    crons = collect_crontabs()
    logs, logs_state = collect_logs(prev_logs, deep=(MODE == "profundo"))
    counters = collect_counters()
    disks = collect_disk()
    sockets = collect_sockets() if MODE == "profundo" else []
    listen_by_pid = collect_listen_ports()

    # índices auxiliares
    children = {}
    for pid, p in procs.items():
        children.setdefault(p["ppid"], []).append(pid)
    pm2_pids = set(str(x["pid"]) for x in pm2 if x.get("pid"))
    th = CFG["thresholds"]
    findings = []

    def add(fp, sev, title, measure, risk=None, fix=None, action=None, tipo="loop", categoria=None):
        findings.append({"fp": fp, "severity": sev, "title": title,
                         "measure": measure, "risk": risk, "fix": fix, "action": action,
                         "tipo": tipo, "categoria": categoria})

    # --- CPU sustentado (delta de ticks entre scans) ---
    for pid, p in procs.items():
        key = "%d:%d" % (pid, p["starttime"])
        prev = prev_procs.get(key)
        if not prev:
            continue
        dticks = p["cpu_ticks"] - prev
        cpu_pct = (dticks / CLK) / wall * 100.0
        if p["comm"] in CFG["cpu_whitelist_comm"]:
            continue
        if cpu_pct >= th["cpu_critical_pct"]:
            r = kill_risk(pid, procs, listen_by_pid, crons, pm2_pids, children)
            add("cpu:%s" % key, "critical",
                "CPU crítica: %s (pid %d) ~%.0f%% sustentado" % (p["comm"], pid, cpu_pct),
                "%.0f%% médio no intervalo de %ds; args: %s" % (cpu_pct, wall, p["args"][:120]),
                "%s — %s" % r, "Investigar antes de matar.")
        elif cpu_pct >= th["cpu_sustained_pct"]:
            r = kill_risk(pid, procs, listen_by_pid, crons, pm2_pids, children)
            add("cpu:%s" % key, "high",
                "CPU alta sustentada: %s (pid %d) ~%.0f%%" % (p["comm"], pid, cpu_pct),
                "%.0f%% médio em %ds; args: %s" % (cpu_pct, wall, p["args"][:120]),
                "%s — %s" % r, None)

    # --- pileup de cron: mesmo SCRIPT de uma linha de cron empilhado (job demora > intervalo) ---
    # Detector estreito (evita o ruído de pools normais tipo postgres/nginx). Só conta scripts
    # (.sh/.js/.py/.mjs) que casam com um comando de cron e que estão acima do esperado.
    sigs = {}
    for pid, p in procs.items():
        if p["ppid"] in (0, 2) or p["comm"].startswith("["):
            continue
        toks = p["args"].split()
        script = next((t for t in toks if t.endswith((".sh", ".js", ".py", ".mjs", ".ts")) and "/" in t), None)
        if script:
            sigs.setdefault(script, []).append(pid)
    for script, pids in sigs.items():
        cj = cron_for_path(crons, os.path.basename(script))
        if not (cj and cj.get("freq_min")):
            continue
        interval = cj["freq_min"] * 60
        # só conta instâncias REALMENTE travadas: vivas há mais que 1,5× o intervalo do cron.
        # Isso descarta a árvore de processos transitória de uma execução normal (segundos de vida).
        stuck = [pid for pid in pids if procs[pid].get("elapsed", 0) > interval * 1.5]
        if len(stuck) >= 3:
            add("pileup:%s" % script, "high",
                "Pileup de cron: %d cópias travadas de '%s'" % (len(stuck), os.path.basename(script)),
                "Cron a cada %dmin, mas %d instâncias rodam há mais que o intervalo — empilhando (job não termina a tempo)." % (cj["freq_min"], len(stuck)),
                "transitório (cron)", "Adicionar trava (flock) ou espaçar o cron `%s`." % cj["schedule"])

    # --- pm2 restart loops ---
    for x in pm2:
        name = x["name"]
        prev = prev_pm2.get(name, {}).get("restarts", x["restarts"])
        delta = x["restarts"] - prev
        if x["status"] != "online":
            add("pm2status:%s" % name, "high",
                "pm2 '%s' fora do ar (status=%s)" % (name, x["status"]),
                "restarts totais=%s" % x["restarts"], "gerenciado pm2",
                "Investigar log: `pm2 logs %s --lines 50`" % name)
        elif delta >= th["pm2_restart_delta"]:
            add("pm2loop:%s" % name, "high",
                "pm2 '%s' em loop de restart" % name,
                "%d restarts no intervalo (total=%s, instáveis=%s)" % (delta, x["restarts"], x["unstable"]),
                "matar é inútil (pm2 ressuscita)",
                "Ver `pm2 logs %s`; estabilizar antes de `pm2 restart`." % name)
        elif x["restarts"] >= th["pm2_restart_total"] and delta > 0:
            add("pm2acc:%s" % name, "medium",
                "pm2 '%s' com restarts acumulados altos" % name,
                "total=%s (subiu %d no intervalo)" % (x["restarts"], delta),
                "gerenciado pm2", "Olhar a causa-raiz dos restarts.")

    # --- systemd restart loops ---
    for s in sysd:
        if s["nrestarts"] >= th["systemd_nrestarts"]:
            add("sysd:%s" % s["unit"], "high",
                "systemd '%s' reiniciando muito" % s["unit"],
                "NRestarts=%d" % s["nrestarts"], "gerenciado systemd",
                "`journalctl -u %s -n 50`; corrigir antes." % s["unit"])

    # --- churn de log + storm de erros (a classe do bug do token) ---
    for L in logs:
        f = L["file"]
        cj = cron_for_path(crons, os.path.basename(f).replace(".log", ""))
        crontxt = (" — cron %s" % cj["schedule"]) if cj else ""
        sev = None
        if L["err_lines"] >= th["log_err_lines_critical"]:
            sev = "critical"
        elif L["err_lines"] >= th["log_err_lines_interval"]:
            sev = "high"
        elif L["appended"] >= th["log_churn_bytes_interval"]:
            sev = "medium"
        if sev:
            add("log:%s" % f, sev,
                "Storm em log: %s" % os.path.basename(f),
                "%d linhas de erro/retry e +%.0fKB desde o último scan%s" % (L["err_lines"], L["appended"]/1024, crontxt),
                "n/a (é log)",
                "Achar o processo/cron que escreve aqui e corrigir backoff/causa. Arquivo: %s" % f,
                action={"type": "rotate_log", "file": f})

    # --- contadores de falha inflados (pegaria o consecutive_rate_limits:649) ---
    for c in counters:
        sev = "high" if c["value"] >= th["counter_value_critical"] else "medium"
        add("counter:%s:%s" % (c["file"], c["key"]), sev,
            "Contador de falha inflado: %s" % c["key"],
            "valor=%s em %s — indica loop de falha persistente." % (c["value"], c["file"]),
            "n/a", "Investigar o serviço dono desse estado; resetar após corrigir a causa.",
            action={"type": "reset_counter", "file": c["file"], "key": c["key"]})

    # --- disco (faxina) ---
    for d in disks:
        add("disk:%s" % d["mount"], "high" if d["pct"] >= 95 else "medium",
            "Disco enchendo: %s em %d%%" % (d["mount"], d["pct"]),
            "Partição %s a %d%%." % (d["mount"], d["pct"]), "n/a",
            "Rotacionar/limpar logs grandes; checar runaway de escrita.",
            tipo="faxina", categoria="Disco")

    # --- storm de conexões EXTERNAS (profundo) ---
    for s in sockets:
        sev = "high" if s.get("cls") == "public" else "medium"
        add("conn:%s" % s["remote"], sev,
            "Muitas conexões a um remoto %s: %s" % (s.get("cls", "?"), s["remote"]),
            "%d conexões established; pids=%s" % (s["conns"], ",".join(s.get("pids", [])) or "?"),
            "ver pid", "Possível storm de requests em voo — checar o processo dono.")

    # =====================================================================
    # FAXINA — manutenção/limpeza (read-only). Portado do Mecânico Preventivo.
    # =====================================================================
    try:
        # inodes altos
        for line in run(["df", "-iP", "-x", "tmpfs", "-x", "devtmpfs"], 10).splitlines()[1:]:
            c = line.split()
            if len(c) >= 6 and c[4].endswith("%"):
                try: pct = int(c[4][:-1])
                except Exception: continue
                if pct >= 85:
                    add("inode:%s" % c[5], "high" if pct >= 95 else "medium",
                        "Inodes quase no limite: %s em %d%%" % (c[5], pct),
                        "Partição %s usa %d%% dos inodes (muitos arquivos pequenos)." % (c[5], pct),
                        "n/a", "Achar e limpar diretório com milhares de arquivos.",
                        tipo="faxina", categoria="Disco")
    except Exception: pass

    try:
        # systemd --failed
        ign = CFG.get("failed_service_ignore", [])
        for line in run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"], 12).splitlines():
            u = line.split()
            if u and u[0].endswith(".service"):
                if any(fnmatch.fnmatch(u[0], pat) for pat in ign):
                    # falha conhecida e benigna (ex.: cloud-init no boot) — informativo, não alerta
                    add("failed:%s" % u[0], "low",
                        "Serviço 'failed' conhecido/benigno: %s" % u[0],
                        "Em estado 'failed' por design (na lista failed_service_ignore do config). Não afeta serviços em execução. journalctl -u %s -n 50" % u[0],
                        "gerenciado systemd", "Ignorável. Tirar do failed_service_ignore se quiser voltar a tratar como problema.",
                        tipo="faxina", categoria="Serviços")
                    continue
                add("failed:%s" % u[0], "high",
                    "Serviço falhou: %s" % u[0],
                    "Unidade em estado 'failed'. journalctl -u %s -n 50" % u[0],
                    "gerenciado systemd", "Ver causa e corrigir; reiniciar só após entender.",
                    tipo="faxina", categoria="Serviços")
    except Exception: pass

    try:
        # serviços-chave inativos
        for s in ["nginx", "docker", "cron", "tailscaled"]:
            st = run(["systemctl", "is-active", s], 6).strip()
            if st and st != "active":
                add("svcdown:%s" % s, "high",
                    "Serviço-chave fora do ar: %s (%s)" % (s, st),
                    "%s não está 'active'." % s, "crítico de base",
                    "Subir o serviço e investigar por que caiu.",
                    tipo="faxina", categoria="Serviços")
    except Exception: pass

    try:
        # docker: contêineres mortos/reiniciando
        out = run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"], 12)
        for line in out.splitlines():
            if re.search(r"unhealthy|Restarting|Exited|dead", line, re.IGNORECASE):
                nm = line.split("\t")[0]
                add("docker:%s" % nm, "medium",
                    "Contêiner problemático: %s" % nm,
                    line.strip(), "ver caso a caso",
                    "Se obsoleto: `docker rm`. Se deveria rodar: investigar o crash.",
                    tipo="faxina", categoria="Containers")
    except Exception: pass

    try:
        # logs grandes (>100MB) — candidatos a rotação (AÇÃO SEGURA)
        out = run(["bash", "-lc", "find /root /var/log -type f -name '*.log' -size +100M 2>/dev/null | head -20"], 20)
        for f in out.split():
            if "/loop-hunter/" in f: continue
            try: mb = os.path.getsize(f) / 1048576
            except Exception: continue
            add("biglog:%s" % f, "medium",
                "Log gigante: %s (%.0fMB)" % (os.path.basename(f), mb),
                "%s ocupa %.0fMB — candidato a rotação." % (f, mb), "n/a (é log)",
                "Rotacionar (backup+trunca). Achar quem escreve tanto.",
                action={"type": "rotate_log", "file": f},
                tipo="faxina", categoria="Logs")
    except Exception: pass

    try:
        # zumbis (sinal inequívoco). NOTA: detecção de vazamento de RAM por threshold foi removida —
        # confunde serviço pesado legítimo (ex.: Bibliotecário RAG ~1.1GB) com vazamento. A versão
        # correta precisa de TENDÊNCIA de RSS ao longo de dias (backlog), não um número fixo.
        zumbis = 0
        for st in run(["ps", "-eo", "stat", "--no-headers"], 10).splitlines():
            if "Z" in st:
                zumbis += 1
        if zumbis > 0:
            add("zombie:all", "low" if zumbis < 5 else "medium",
                "%d processo(s) zumbi" % zumbis,
                "Zumbis não somem sozinhos — indica pai que não fez wait().", "ver pai",
                "Identificar e reiniciar o processo-pai.", tipo="faxina", categoria="Processos")
    except Exception: pass

    if MODE == "profundo":
        try:
            # certificados SSL expirando (<21 dias)
            import glob as _g
            for cpem in _g.glob("/etc/letsencrypt/live/*/cert.pem"):
                dom = os.path.basename(os.path.dirname(cpem))
                end = run(["openssl", "x509", "-enddate", "-noout", "-in", cpem], 8).strip()
                end = end.split("=", 1)[1] if "=" in end else ""
                ends = run(["date", "-d", end, "+%s"], 6).strip() if end else ""
                if ends.isdigit():
                    days = (int(ends) - NOW) // 86400
                    if days < 21:
                        add("cert:%s" % dom, "high" if days < 7 else "medium",
                            "Certificado SSL expira em %d dias: %s" % (days, dom),
                            "%s vence em %d dias." % (dom, days), "n/a",
                            "Renovar (certbot). Checar por que o auto-renew não pegou.",
                            tipo="faxina", categoria="Certificados")
        except Exception: pass
        try:
            # atualizações de segurança pendentes
            up = run(["bash", "-lc", "apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep -ci security"], 25).strip()
            if up.isdigit() and int(up) > 0:
                add("apt:security", "medium",
                    "%s atualização(ões) de segurança pendente(s)" % up,
                    "%s pacotes de segurança aguardando." % up, "n/a",
                    "Revisar e aplicar `apt upgrade` em janela segura (via Claude).",
                    tipo="faxina", categoria="Atualizações")
        except Exception: pass

    # ---- SILÊNCIO/HEARTBEAT + BACKUPS: lista CURADA de logs que escrevem a cada execução ----
    # (auto-derivar do cron dá falso-positivo: muitos jobs logam só em evento, ou logam noutro
    #  arquivo. Lista curada em config.json -> "heartbeats": [{name, log, max_age_h, tipo}].)
    try:
        _hbs = CFG.get("heartbeats", {})
        _hb_list = _hbs.get(vps_name(), []) if isinstance(_hbs, dict) else _hbs
        for hb in _hb_list:
            lf = hb.get("log")
            if not lf:
                continue
            try:
                age_h = (NOW - os.path.getmtime(lf)) / 3600.0
            except Exception:
                # log inexistente também é sinal (nunca rodou / sumiu)
                add("silence:%s" % lf, "high",
                    "Sem heartbeat: %s" % hb.get("name", os.path.basename(lf)),
                    "O log esperado (%s) não existe — o job pode nunca ter rodado." % lf,
                    "n/a", "Verificar o cron/script.", tipo="faxina",
                    categoria=("Backups" if hb.get("tipo") == "backup" else "Pipelines"))
                continue
            if age_h > hb.get("max_age_h", 26):
                is_bk = hb.get("tipo") == "backup"
                add("silence:%s" % lf, "high",
                    ("Backup pode não estar rodando: %s" if is_bk else "Pipeline parado: %s") % hb.get("name", os.path.basename(lf)),
                    "O heartbeat '%s' está %dh sem atividade (limite: %dh) — provavelmente parou." % (hb.get("name", lf), age_h, hb.get("max_age_h", 26)),
                    "n/a", "Rodar o job na mão e ver o erro; corrigir a causa.",
                    tipo="faxina", categoria=("Backups" if is_bk else "Pipelines"))
    except Exception:
        pass

    # ---- MEMÓRIA / SWAP ----
    try:
        mi = {}
        for line in open("/proc/meminfo"):
            pp = line.split(":")
            if len(pp) == 2:
                mi[pp[0]] = int(pp[1].strip().split()[0])  # kB
        total = mi.get("MemTotal", 0)
        avail = mi.get("MemAvailable", mi.get("MemFree", 0))
        swt = mi.get("SwapTotal", 0); swf = mi.get("SwapFree", 0)
        if total and avail / total < 0.06:
            add("mem:low", "high", "RAM no limite: só %d%% disponível" % (avail * 100 // total),
                "Memória disponível muito baixa (%dMB de %dMB) — risco de travar/matar processo." % (avail // 1024, total // 1024),
                "n/a", "Achar o que consome RAM; reiniciar o serviço ou aumentar memória.",
                tipo="faxina", categoria="Memória")
        if swt and (swt - swf) > 512 * 1024 and (swt - swf) / swt > 0.75 and total and avail / total < 0.20:
            add("swap:high", "high", "Swap pesado + RAM baixa",
                "Swap %d%% usado com RAM disponível baixa — a VPS está sob pressão de memória." % ((swt - swf) * 100 // swt),
                "n/a", "Investigar consumo de memória; pode estar degradando tudo.",
                tipo="faxina", categoria="Memória")
    except Exception:
        pass

    # ---- DISCO: montagem só-leitura + reboot pendente ----
    try:
        for line in open("/proc/mounts"):
            pp = line.split()
            if len(pp) >= 4 and pp[1] in ("/", "/var", "/var/log", "/root", "/home") \
               and "ro" in pp[3].split(","):
                add("romount:%s" % pp[1], "high", "Disco montado SÓ-LEITURA: %s" % pp[1],
                    "A partição %s está read-only — sinal de erro de disco/filesystem. GRAVE." % pp[1],
                    "n/a", "Ver dmesg por erro de disco; pode exigir fsck/reboot.",
                    tipo="faxina", categoria="Disco")
        if os.path.exists("/var/run/reboot-required"):
            add("reboot:pending", "low", "Reboot pendente (update de kernel)",
                "Um update (provavelmente kernel) pede reboot pra ativar.", "n/a",
                "Agendar reboot em janela tranquila.", tipo="faxina", categoria="Sistema")
    except Exception:
        pass

    if MODE == "profundo":
        try:
            oom = run(["bash", "-lc", "journalctl -k --since '24 hours ago' --no-pager 2>/dev/null | grep -ciE 'killed process|out of memory'"], 25).strip()
            if oom.isdigit() and int(oom) > 0:
                add("oom:recent", "high", "Falta de memória matou processo(s)",
                    "O OOM killer atuou %s vez(es) nas últimas 24h — a VPS ficou sem RAM." % oom,
                    "n/a", "Ver o que estourou a memória; ajustar/limitar o serviço.",
                    tipo="faxina", categoria="Memória")
        except Exception:
            pass
        try:
            io = run(["bash", "-lc", "journalctl -k --since '24 hours ago' --no-pager 2>/dev/null | grep -ciE 'I/O error|EXT4-fs error|remounting read-only|critical medium error'"], 25).strip()
            if io.isdigit() and int(io) > 0:
                add("ioerror:kernel", "high", "Erros de disco no kernel (%sx/24h)" % io,
                    "O kernel registrou erros de I/O/filesystem — possível disco com problema.",
                    "n/a", "Olhar dmesg/journal; avaliar saúde do disco com urgência.",
                    tipo="faxina", categoria="Disco")
        except Exception:
            pass
        # ---- RAIO-X DE EXPOSIÇÃO ----
        try:
            exp = collect_exposure()
            for e in exp["exposed"]:
                sev = "high" if e["sensitive"] else "medium"
                tit = ("Serviço sensível" if e["sensitive"] else "Porta") + " aberto(a) pra INTERNET: %d (%s)" % (e["port"], e["proc"])
                why = ("Banco/cache acessível da internet = risco de vazamento de dados." if e["sensitive"]
                       else "App exposto direto (fora do nginx) — confirmar se é intencional; sem nginx não há proteção/TLS na frente.")
                add("exposure:%d" % e["port"], sev, tit,
                    "Escuta em 0.0.0.0:%d e o ufw libera de qualquer origem. %s" % (e["port"], why),
                    "n/a", "Fechar a porta no ufw, OU amarrar o serviço a 127.0.0.1/Tailscale, OU pôr atrás do nginx.",
                    tipo="faxina", categoria="Exposição")
            if exp["ufw"] == "inactive":
                add("ufw:off", "high", "Firewall (ufw) DESLIGADO",
                    "O firewall local está inativo — tudo que escuta em 0.0.0.0 fica aberto pra internet.",
                    "n/a", "Reativar o ufw com as regras corretas (urgente).", tipo="faxina", categoria="Exposição")
            if exp["fail2ban"] not in ("active", "?"):
                add("fail2ban:off", "medium", "fail2ban parado",
                    "O fail2ban (bloqueia força-bruta de senha) não está ativo (%s)." % exp["fail2ban"],
                    "n/a", "Reativar: systemctl enable --now fail2ban.", tipo="faxina", categoria="Exposição")
            if exp["ssh"].get("root") == "yes" and exp["ssh"].get("passwd") == "yes":
                add("ssh:rootpw", "high", "SSH permite login root com SENHA",
                    "PermitRootLogin yes + PasswordAuthentication yes — alvo fácil de força-bruta.",
                    "n/a", "Mudar p/ key-only: PermitRootLogin prohibit-password + PasswordAuthentication no.",
                    tipo="faxina", categoria="Exposição")
            fails = run(["bash", "-lc", "journalctl -u ssh --since '24 hours ago' --no-pager 2>/dev/null | grep -ciE 'Failed password|Invalid user'"], 20).strip()
            if fails.isdigit() and int(fails) > 100:
                add("sshattack:24h", "medium", "SSH sob ataque de força-bruta",
                    "%s tentativas falhas em 24h — alguém martelando o SSH (porta 22 alcançável da internet)." % fails,
                    "n/a", "O fail2ban deve estar bloqueando; considere fechar a 22 p/ só-Tailscale.",
                    tipo="faxina", categoria="Exposição")
        except Exception:
            pass

    # ---- RECURSOS (hardware) + PREVISÃO de disco cheio ----
    hw = collect_hardware()
    try:
        HIST = os.path.join(STATE_DIR, "hw-history.json")
        hist = [e for e in load_json(HIST, []) if isinstance(e, dict)]  # formato novo (dict)
        root = next((d for d in hw["disks"] if d["mount"] == "/"), None)
        if MODE == "profundo" and root:
            hist.append({"ts": NOW, "du": root["used_gb"], "dt": root["total_gb"], "dp": root["pct"],
                         "mp": hw.get("mem", {}).get("pct", 0),
                         "l1": (hw.get("load") or [0])[0]})
            hist = hist[-45:]
            try: json.dump(hist, open(HIST, "w"))
            except Exception: pass
        if root and len(hist) >= 3:
            span = (hist[-1]["ts"] - hist[0]["ts"]) / 86400.0
            rate = (hist[-1]["du"] - hist[0]["du"]) / span if span >= 1 else 0   # GB/dia
            if rate > 0.05:
                free_gb = root["total_gb"] - root["used_gb"]
                days = free_gb / rate
                if days < 14:
                    add("diskpredict:/", "high" if days < 7 else "medium",
                        "Disco vai encher em ~%d dias" % int(days),
                        "/ enchendo ~%.1fGB/dia; faltam %.0fGB → cheio em ~%d dias no ritmo atual." % (rate, free_gb, days),
                        "n/a", "Achar o que cresce (logs? uploads?) e limpar/rotacionar antes de encher.",
                        tipo="faxina", categoria="Disco")
    except Exception:
        pass

    inv = collect_inventory() if MODE == "profundo" else None

    new_snap = {
        "ts": NOW,
        "procs": {"%d:%d" % (p["pid"], p["starttime"]): p["cpu_ticks"] for p in procs.values()},
        "pm2": {x["name"]: {"restarts": x["restarts"]} for x in pm2},
        "logs": logs_state,
    }
    return findings, new_snap, {"procs": len(procs), "pm2": len(pm2),
                                "logs_checked": len(logs), "hardware": hw, "inventory": inv}

# =========================================================================
# Dedupe / cooldown / alerta / relatório
# =========================================================================
def severity_emoji(s):
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}.get(s, "•")

def main():
    findings, new_snap, stats = analyze()
    findings.sort(key=lambda f: -SEV_RANK.get(f["severity"], 0))

    # estado de fingerprints p/ cooldown
    fstate = load_json(FIND_FILE, {})
    cooldown = CFG["alert_cooldown_sec"]
    minsev = SEV_RANK[CFG["alert_min_severity"]]
    to_alert = []
    for f in findings:
        if SEV_RANK[f["severity"]] < minsev:
            continue
        last = fstate.get(f["fp"], {}).get("last_alert", 0)
        if NOW - last >= cooldown:
            to_alert.append(f)
            fstate[f["fp"]] = {"last_alert": NOW, "severity": f["severity"], "title": f["title"]}
    # limpa fingerprints velhos (>3 dias sem reaparecer)
    seen = set(f["fp"] for f in findings)
    fstate = {k: v for k, v in fstate.items() if k in seen or NOW - v.get("last_alert", 0) < 3*86400}

    # --- relatório markdown (sempre) ---
    write_report(findings, stats)

    # --- persiste estado ---
    try:
        json.dump(new_snap, open(SNAP_FILE, "w"))
        json.dump(fstate, open(FIND_FILE, "w"))
    except Exception as e:
        sys.stderr.write("erro salvando estado: %s\n" % e)

    # --- dispara alerta (só novidades high/critical) ---
    if to_alert:
        send_alert(to_alert, findings)

    print(json.dumps({"mode": MODE, "stats": stats,
                      "findings": len(findings),
                      "by_sev": {s: sum(1 for f in findings if f["severity"] == s)
                                 for s in SEV_RANK},
                      "alerted": len(to_alert)}, ensure_ascii=False))

def write_report(findings, stats):
    code = CFG.get("resume_code", "cacaloop")
    vps = vps_name()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    by = {s: [f for f in findings if f["severity"] == s] for s in ("critical", "high", "medium", "low")}
    lines = []
    lines.append("# Caça-Loops — %s" % vps)
    lines.append("_Scan %s · %s · processos=%d pm2=%d logs=%d_" %
                 (MODE, ts, stats["procs"], stats["pm2"], stats["logs_checked"]))
    lines.append("")
    tot = len(findings)
    if tot == 0:
        lines.append("✅ **Nenhum loop/desperdício detectado neste scan.**")
    else:
        lines.append("**%d achado(s):** 🔴%d crítico · 🟠%d alto · 🟡%d médio · ⚪%d baixo" %
                     (tot, len(by["critical"]), len(by["high"]), len(by["medium"]), len(by["low"])))
        for sev in ("critical", "high", "medium", "low"):
            for f in by[sev]:
                lines.append("")
                lines.append("## %s %s" % (severity_emoji(sev), f["title"]))
                lines.append("- **Medição:** %s" % f["measure"])
                if f.get("risk"):
                    lines.append("- **Risco de matar:** %s" % f["risk"])
                if f.get("fix"):
                    lines.append("- **Ação recomendada:** %s" % f["fix"])
    lines.append("")
    lines.append("---")
    lines.append("_Para aprofundar e tratar: abra o Claude Code e digite **`%s`**._" % code)
    out = "\n".join(lines) + "\n"
    try:
        open(os.path.join(REPORT_DIR, "latest.md"), "w").write(out)
        open(os.path.join(REPORT_DIR, "%s.md" % time.strftime("%Y-%m-%d")), "w").write(out)
    except Exception as e:
        sys.stderr.write("erro escrevendo relatorio: %s\n" % e)
    # JSON estruturado p/ o painel
    try:
        out_f = []
        for f in findings:
            k = fp_kind(f["fp"])
            cat = f.get("categoria") or LOOP_CAT.get(k, "Outros")
            out_f.append(dict(f, kind=k, categoria=cat, code=item_code(f["fp"], vps),
                              tipo=f.get("tipo", "loop")))
        # carry-forward: scan LEVE preserva achados profundo-only (apt/cert/conn) do último
        # profundo, senão o cron de 15min apagaria o que só o scan diário detecta.
        if MODE == "leve":
            try:
                prev = json.load(open(os.path.join(REPORT_DIR, "latest.json")))
                cur = set(f["fp"] for f in findings)
                for pf in prev.get("findings", []):
                    if pf.get("kind") in ("cert", "apt", "conn_storm") and pf.get("fp") not in cur:
                        out_f.append(pf)
            except Exception:
                pass
        data = {"vps": vps, "ts": NOW, "ts_human": ts, "mode": MODE, "stats": stats,
                "hardware": stats.get("hardware"), "findings": out_f}
        open(os.path.join(REPORT_DIR, "latest.json"), "w").write(
            json.dumps(data, ensure_ascii=False))
        # inventário (mapa da casa) — só no profundo (não sobrescreve com None no leve)
        if stats.get("inventory"):
            open(os.path.join(REPORT_DIR, "inventory.json"), "w").write(
                json.dumps({"vps": vps, "ts": NOW, "ts_human": ts, "inventory": stats["inventory"]}, ensure_ascii=False))
        # ---- JOURNAL de eventos p/ o relatório semanal (apareceu/resolvido) ----
        openf = os.path.join(STATE_DIR, "open.json")
        evf = os.path.join(STATE_DIR, "events.jsonl")
        prev_open = load_json(openf, {})
        # "since" = desde quando o achado está aberto (carrega do scan anterior).
        # É a base da COBRANÇA TEIMOSA (cobranca.py): achado vermelho velho vira cobrança diária.
        cur_open = {f["fp"]: {"title": f["title"], "severity": f["severity"],
                              "code": f["code"], "categoria": f.get("categoria"),
                              "since": (prev_open.get(f["fp"]) or {}).get("since") or NOW}
                    for f in out_f}
        SEVOK = ("medium", "high", "critical")
        evs = []
        for fp, info in cur_open.items():
            if fp not in prev_open and info["severity"] in SEVOK:
                evs.append({"ts": NOW, "ev": "apareceu", "vps": vps, "code": info["code"],
                            "title": info["title"], "severity": info["severity"]})
        for fp, info in prev_open.items():
            if fp not in cur_open and info.get("severity") in SEVOK:
                evs.append({"ts": NOW, "ev": "resolvido", "vps": vps, "code": info.get("code"),
                            "title": info.get("title"), "severity": info.get("severity")})
        if evs:
            with open(evf, "a") as fh:
                for e in evs:
                    fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        json.dump(cur_open, open(openf, "w"), ensure_ascii=False)
        try:   # poda eventos > 14 dias
            cutoff = NOW - 14 * 86400
            ls = [l for l in open(evf).read().splitlines() if l.strip()]
            keep = [l for l in ls if json.loads(l).get("ts", NOW) >= cutoff]
            if len(keep) != len(ls):
                open(evf, "w").write(("\n".join(keep) + "\n") if keep else "")
        except Exception:
            pass
    except Exception as e:
        sys.stderr.write("erro escrevendo json/journal: %s\n" % e)

def fp_kind(fp):
    p = fp.split(":", 1)[0]
    return {"log": "log_storm", "counter": "counter", "cpu": "cpu",
            "pm2loop": "pm2_loop", "pm2status": "pm2_status", "pm2acc": "pm2_loop",
            "sysd": "systemd_loop", "pileup": "cron_pileup", "conn": "conn_storm",
            "disk": "disk", "inode": "inode", "failed": "failed_service",
            "svcdown": "svc_down", "docker": "docker_dead", "biglog": "big_log",
            "zombie": "zombie", "orphan": "orphan", "cert": "cert", "apt": "apt",
            "silence": "silence", "backupstale": "backup", "mem": "mem_low",
            "swap": "swap_high", "oom": "oom", "romount": "romount",
            "ioerror": "ioerror", "reboot": "reboot", "diskpredict": "disk_predict",
            "exposure": "exposure", "ufw": "firewall", "fail2ban": "fail2ban_off",
            "ssh": "ssh_posture", "sshattack": "ssh_attack"}.get(p, "other")

LOOP_CAT = {"log_storm": "Logs", "counter": "Estado", "cpu": "Processos",
            "pm2_loop": "Serviços", "pm2_status": "Serviços", "systemd_loop": "Serviços",
            "cron_pileup": "Processos", "conn_storm": "Rede", "disk": "Disco", "other": "Outros"}

def item_code(fp, vps=""):
    return "fx" + hashlib.md5((vps + ":" + fp).encode("utf-8")).hexdigest()[:4]

def send_alert(to_alert, all_findings):
    vps = vps_name()
    n_c = sum(1 for f in to_alert if f["severity"] == "critical")
    n_h = sum(1 for f in to_alert if f["severity"] == "high")
    body = ["🧹 *Faxina · %s* — %d novo(s) achado(s) (🔴%d 🟠%d):" % (vps, len(to_alert), n_c, n_h)]
    first_code = "fxXXXX"
    for i, f in enumerate(to_alert[:6]):
        c = item_code(f["fp"], vps)
        if i == 0:
            first_code = c
        body.append("%s *%s* — %s\n   ↳ %s" % (severity_emoji(f["severity"]), c, f["title"], f["measure"]))
    if len(to_alert) > 6:
        body.append("...e mais %d." % (len(to_alert) - 6))
    panel = CFG.get("panel_url")
    body.append("")
    if panel:
        body.append("📊 Painel: %s" % panel)
    body.append("Pra aprofundar/corrigir, digite no Claude Code o *código do item* (ex: %s) — ou *faxina* pra ver tudo. (só-alerta: nada foi mexido)" % first_code)
    msg = "\n".join(body)
    if os.environ.get("LOOPHUNTER_DRY"):
        sys.stderr.write("=== DRY-RUN, alerta NÃO enviado ===\n%s\n=== fim ===\n" % msg)
        return
    notify = os.path.join(BASE, "notify.sh")
    try:
        subprocess.run(["bash", notify, msg], timeout=40)
    except Exception as e:
        sys.stderr.write("falha no notify: %s\n" % e)

if __name__ == "__main__":
    main()
