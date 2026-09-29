# VPS Guardian

**A server that watches itself: it finds loops, silent failures and exposed ports before they cost money, and tells you in plain language.**

## The problem

A small redundant cron job on my server got rate-limited by an API and kept retrying for **about 13 days**. Its failure counter climbed to **649**. Nothing crashed, nobody got an alert, and nobody noticed.

That is the most expensive type of failure for a small team: the one that fails quietly. Standard uptime monitors only check whether the box is up, and this box was up the whole time.

## What I built

A local monitor that runs every 15 minutes and looks for the problems uptime checks miss:

| Layer | What it catches |
|---|---|
| **Loop hunter** | Error/retry storms in logs, inflated failure counters, runaway CPU, restart loops (pm2/systemd), piled-up cron jobs, connection storms |
| **Housekeeping** | Disk and inodes, failed services, dead containers, giant logs, SSL certificates close to expiry, pending security updates |
| **Silent failures** | Pipelines or backups that stopped running (heartbeats), out-of-memory kills, read-only disk, pending reboot |
| **Resources** | CPU, RAM, disk and swap, plus a forecast of when the disk will be full ("full in ~N days") |
| **Exposure X-ray** | What is *really* open to the internet: listening ports cross-checked with the firewall, so no false alarms. Also checks SSH/fail2ban posture |
| **House map** | Live inventory of processes, containers, services, crons, ports and subdomains, with dead backends highlighted |
| **Who watches the watcher** | A separate systemd timer warns you, through a backup channel, if the monitor itself stops |
| **Undo button** | Daily git snapshot of critical configs (nginx, crontabs, systemd, pm2), with secrets redacted, so every change can be reverted |
| **Weekly report** | Every Monday morning: how the server is doing, what to worry about and what changed |

## Design decisions

- **Only alert on what is serious.** High and critical findings go to Telegram (with WhatsApp as backup). Everything else stays on the dashboard. A 6-hour cooldown per finding keeps alerts from turning into noise.
- **Detection makes zero external requests.** It only reads local state, so the monitor can never become the next runaway process. Only the notifier touches the network.
- **Human in the loop.** The monitor never kills, deletes or restarts anything on its own. The dashboard can only run two allowlisted safe actions (reset a counter, rotate a log). Anything else needs an explicit OK.
- **Every finding has a short code** (e.g. `fx3a9c`), so it can be handed to a coding agent to investigate in one line.
- **Private by default.** The dashboard is reachable only inside a Tailscale network, and the nginx vhost rejects any other origin.

## Structure

```
scanner/   hunt.py (the detector), notify.sh, act.sh (allowlisted actions),
           weekly-report.py, cobranca.py (daily follow-up), watchdog.sh, snapshot-config.sh, install-cron.sh,
           config.example.json
panel/     server.js: read-only web dashboard (Node, no dependencies)
deploy/    systemd watchdog timer + nginx vhost (Tailscale-only)
```

It uses no third-party packages: Python standard library, bash and plain Node. Messages and code comments are in Portuguese.

## Running it

1. Copy `scanner/` to `/root/loop-hunter/` and `config.example.json` to `config.json`. Fill in your alert channel, your heartbeats and your thresholds.
2. Dry run, without sending anything: `LOOPHUNTER_DRY=1 python3 hunt.py --profundo`.
3. `bash install-cron.sh` installs the scans (light every 15 min, deep once a day). Add cron lines for `snapshot-config.sh` (daily), `cobranca.py` (daily follow-up on open findings) and `weekly-report.py` (Mondays).
4. Optional: run `panel/server.js` behind the nginx vhost in `deploy/`, and enable the watchdog timer.

## How it was built

AI-native: I wrote the spec from a real incident, directed coding agents to build it, and kept refining it with what showed up in production on my own server. It has run on my server every 15 minutes since June 2026.

---

Thiago Lourenço Martins · [LinkedIn](https://www.linkedin.com/in/thiago-lourenco-martins) · [loumart.com.br](https://loumart.com.br)
