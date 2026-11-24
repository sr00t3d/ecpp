#!/usr/bin/env bash
# ==============================================================================
# ecpp.sh — Exim & Mail Log Forensics / Outbound Spam Analyzer CLI (v2.0.0)
# Modernized clean-room implementation inspired by ecpp_2.pl (2009-2013, Michael Karr).
# Copyright (c) 2026 Percio Castelo — Apache-2.0 License
# ==============================================================================
set -euo pipefail

VERSION="2.0.0"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required (3.6+)." >&2
    exit 1
fi

read -r -d '' PY_SCRIPT << 'EOF' || true
import argparse
import collections
import csv
import datetime
import glob
import gzip
import io
import json
import os
import re
import sys

VERSION = "2.0.0"

EXIM_TS_RX = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$")
AUTH_RX = re.compile(r"\bA=(?:dovecot_login|dovecot_plain|courier_login|courier_plain|fixed_plain|login):([^\s]+)")
HOST_IP_RX = re.compile(r"\bH=[^\[]*\[([0-9a-fA-F.:]+)\]")
CWD_RX = re.compile(r"\bcwd=([^\s]+)")
SUBJ_RX = re.compile(r'\bT="((?:[^"\\]|\\.)*)"')
FROM_RX = re.compile(r"<=\s+([^\s]+)")
TO_RX = re.compile(r"=>\s+([^\s]+)")
BOUNCE_RX = re.compile(r"\*\*\s+([^\s]+)")
MAIL_TS_RX = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+")
MAIL_LOGIN_RX = re.compile(r"(?:dovecot|courier).*?(?:user=<([^>]+)>|Login:\s+user=<([^>]+)>).*?rip=([0-9a-fA-F.:]+)")


class Colors:
    def __init__(self, enabled=True):
        self.RESET = "\033[0m" if enabled else ""
        self.BOLD = "\033[1m" if enabled else ""
        self.CYAN = "\033[36m" if enabled else ""
        self.GREEN = "\033[32m" if enabled else ""
        self.YELLOW = "\033[33m" if enabled else ""
        self.RED = "\033[31m" if enabled else ""
        self.DIM = "\033[2m" if enabled else ""


def open_maybe_gz(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def load_domain_maps(etc_root):
    user2dom = collections.defaultdict(list)
    dom2user = {}
    ud_file = os.path.join(etc_root, "userdomains")
    if os.path.isfile(ud_file):
        with open(ud_file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if ":" in line:
                    dom, usr = line.split(":", 1)
                    dom = dom.strip().lower()
                    usr = usr.strip()
                    if dom and usr and usr != "nobody":
                        dom2user[dom] = usr
                        user2dom[usr].append(dom)

    owner2users = collections.defaultdict(list)
    tuo_file = os.path.join(etc_root, "trueuserowners")
    if os.path.isfile(tuo_file):
        with open(tuo_file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if ":" in line:
                    usr, owner = line.split(":", 1)
                    owner2users[owner.strip()].append(usr.strip())
    return user2dom, dom2user, owner2users


def resolve_targets(target, reseller_mode, etc_root):
    user2dom, dom2user, owner2users = load_domain_maps(etc_root)
    if target.lower() in ("root", "all", "*"):
        return set(), set(), True

    users = set()
    domains = set()
    if reseller_mode:
        for u in owner2users.get(target, []):
            users.add(u)
            domains.update(user2dom.get(u, []))
    elif target.lower() in dom2user:
        u = dom2user[target.lower()]
        users.add(u)
        domains.add(target.lower())
    else:
        users.add(target)
        domains.update(user2dom.get(target, []))
        if "." in target:
            domains.add(target.lower())
    return users, domains, False


def discover_logs(explicit_paths, defaults):
    files = []
    if explicit_paths:
        for p in explicit_paths.split(","):
            files.extend(glob.glob(p.strip()))
    else:
        for pattern in defaults:
            files.extend(glob.glob(pattern))
    return sorted(set(f for f in files if os.path.isfile(f)))


def find_mail_creation(email_addr, cpanel_log_dir):
    if "@" not in email_addr:
        sys.stderr.write(f"Error: invalid email address '{email_addr}'.\n")
        sys.exit(1)
    user, dom = email_addr.split("@", 1)
    logs = []
    main_log = os.path.join(cpanel_log_dir, "access_log")
    if os.path.isfile(main_log):
        logs.append(main_log)
    logs.extend(sorted(glob.glob(os.path.join(cpanel_log_dir, "archive", "access_log-*.gz")), reverse=True))

    rx = re.compile(rf"addpop&email={re.escape(user)}.*?domain={re.escape(dom)}")
    matches = []
    for lf in logs:
        try:
            with open_maybe_gz(lf) as fh:
                for line in fh:
                    if rx.search(line):
                        matches.append({"file": lf, "entry": line.strip()})
                        break
        except OSError:
            continue
        if matches:
            break
    return matches


def analyze_logs(args):
    users, domains, scan_all = resolve_targets(args.target, args.reseller, args.etc_root)
    hours = args.days * 24 if args.days else args.hours
    now = datetime.datetime.now()
    start_dt = now - datetime.timedelta(hours=hours)
    end_dt = now - datetime.timedelta(hours=args.end_hours) if args.end_hours else now

    exim_files = discover_logs(
        args.exim_log,
        ["/var/log/exim_mainlog*", "/var/log/exim4/mainlog*"],
    )
    mail_files = discover_logs(
        args.mail_log,
        ["/var/log/maillog*", "/var/log/mail.log*"],
    )

    stats = {
        "target": args.target,
        "window_start": start_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "window_end": end_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "sent_count": 0,
        "delivered_count": 0,
        "bounce_count": 0,
        "unique_recipients": 0,
        "top_senders": [],
        "top_auth_ips": [],
        "top_cwds": [],
        "top_subjects": [],
        "top_recipients": [],
        "hourly": {},
        "imap_pop_ips": [],
        "logs_scanned": exim_files + mail_files,
    }

    senders = collections.Counter()
    auth_ips = collections.Counter()
    cwds = collections.Counter()
    subjects = collections.Counter()
    recipients = collections.Counter()
    hourly = collections.Counter()
    imap_ips = collections.Counter()
    matched_msg_ids = set()

    def line_matches_target(rest, sender_addr, auth_user, cwd_val):
        if scan_all:
            return True
        for u in users:
            if f"/home/{u}/" in cwd_val or cwd_val.endswith(f"/{u}") or f"U={u}" in rest or auth_user == u:
                return True
        for d in domains:
            if f"@{d}" in sender_addr.lower() or f"@{d}" in auth_user.lower():
                return True
        return False

    for lf in exim_files:
        try:
            with open_maybe_gz(lf) as fh:
                for line in fh:
                    m = EXIM_TS_RX.match(line)
                    if not m:
                        continue
                    ts_str, msg_id, rest = m.groups()
                    try:
                        dt = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        continue
                    if not args.no_time_filter and (dt < start_dt or dt > end_dt):
                        continue

                    if rest.startswith("<="):
                        fm = FROM_RX.search(rest)
                        sender = fm.group(1) if fm else ""
                        am = AUTH_RX.search(rest)
                        auth_u = am.group(1) if am else ""
                        cm = CWD_RX.search(rest)
                        cwd_v = cm.group(1) if cm else ""
                        if line_matches_target(rest, sender, auth_u, cwd_v):
                            matched_msg_ids.add(msg_id)
                            stats["sent_count"] += 1
                            senders[auth_u or sender or "(local)"] += 1
                            hourly[dt.strftime("%Y-%m-%d %H:00")] += 1
                            hm = HOST_IP_RX.search(rest)
                            if hm:
                                auth_ips[hm.group(1)] += 1
                            if cwd_v:
                                cwds[cwd_v] += 1
                            sm = SUBJ_RX.search(rest)
                            if sm:
                                subjects[sm.group(1)[:80]] += 1
                    elif rest.startswith("=>") and msg_id in matched_msg_ids:
                        stats["delivered_count"] += 1
                        tm = TO_RX.search(rest)
                        if tm:
                            recipients[tm.group(1)] += 1
                    elif rest.startswith("**") and msg_id in matched_msg_ids:
                        stats["bounce_count"] += 1
        except OSError:
            continue

    for lf in mail_files:
        try:
            with open_maybe_gz(lf) as fh:
                for line in fh:
                    lm = MAIL_LOGIN_RX.search(line)
                    if lm:
                        u = lm.group(1) or lm.group(2) or ""
                        ip = lm.group(3)
                        if scan_all or any(u == usr or f"@{d}" in u.lower() for usr in users for d in domains) or any(f"@{d}" in u.lower() for d in domains) or u in users:
                            imap_ips[f"{ip} ({u})"] += 1
        except OSError:
            continue

    stats["unique_recipients"] = len(recipients)
    stats["top_senders"] = [{"sender": k, "count": v} for k, v in senders.most_common(10)]
    stats["top_auth_ips"] = [{"ip": k, "count": v} for k, v in auth_ips.most_common(10)]
    stats["top_cwds"] = [{"cwd": k, "count": v} for k, v in cwds.most_common(10)]
    stats["top_subjects"] = [{"subject": k, "count": v} for k, v in subjects.most_common(10)]
    stats["top_recipients"] = [{"recipient": k, "count": v} for k, v in recipients.most_common(10)]
    stats["hourly"] = dict(sorted(hourly.items()))
    stats["imap_pop_ips"] = [{"session": k, "count": v} for k, v in imap_ips.most_common(10)]
    return stats


def render_table(stats, c):
    print(f"{c.BOLD}{c.CYAN}=== ecpp.sh v{VERSION} | Mail Log Forensics Report ==={c.RESET}")
    print(f"  {c.BOLD}Target:{c.RESET}     {stats['target']}")
    print(f"  {c.BOLD}Window:{c.RESET}     {stats['window_start']} -> {stats['window_end']}")
    print(f"  {c.BOLD}Summary:{c.RESET}    Sent: {c.GREEN}{stats['sent_count']}{c.RESET} | Delivered: {stats['delivered_count']} | Bounces: {c.RED}{stats['bounce_count']}{c.RESET} | Unique Recips: {stats['unique_recipients']}")

    sections = [
        ("Top Senders / Auth", stats["top_senders"], "sender"),
        ("Top Source IPs", stats["top_auth_ips"], "ip"),
        ("Top Script CWDs", stats["top_cwds"], "cwd"),
        ("Top Subjects", stats["top_subjects"], "subject"),
        ("IMAP/POP3 Logins", stats["imap_pop_ips"], "session"),
    ]
    for title, items, key in sections:
        if items:
            print(f"\n{c.BOLD}{c.YELLOW}--- {title} ---{c.RESET}")
            for it in items:
                print(f"  {it['count']:>5}  {it[key]}")

    if stats["hourly"]:
        print(f"\n{c.BOLD}{c.CYAN}--- Hourly Volume ---{c.RESET}")
        for hr, cnt in stats["hourly"].items():
            print(f"  {hr}  {cnt}")


def render_csv(stats):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["target", "window_start", "window_end", "sent", "delivered", "bounces", "unique_recipients"])
    w.writerow([
        stats["target"], stats["window_start"], stats["window_end"],
        stats["sent_count"], stats["delivered_count"], stats["bounce_count"], stats["unique_recipients"],
    ])
    sys.stdout.write(buf.getvalue())


def main():
    parser = argparse.ArgumentParser(
        prog="ecpp.sh",
        description="Exim & Mail Log Forensics / Outbound Spam Analyzer CLI (v2.0.0)",
    )
    parser.add_argument("target", nargs="?", help="Username, domain, reseller, or 'root'/'all'")
    parser.add_argument("-H", "--hours", type=int, default=48, help="Hours back to scan (default: 48)")
    parser.add_argument("-e", "--end-hours", type=int, default=0, help="End window N hours ago (default: 0)")
    parser.add_argument("-d", "--days", type=int, default=0, help="Days back to scan (overrides --hours)")
    parser.add_argument("-r", "--reseller", action="store_true", help="Treat target as cPanel reseller")
    parser.add_argument("-c", "--create", metavar="EMAIL", help="Find creation log entry for email address")
    parser.add_argument("--exim-log", help="Comma-separated Exim log paths/globs")
    parser.add_argument("--mail-log", help="Comma-separated IMAP/POP3 maillog paths/globs")
    parser.add_argument("--cpanel-log-dir", default="/usr/local/cpanel/logs", help="cPanel logs directory")
    parser.add_argument("--etc-root", default="/etc", help="Custom /etc root")
    parser.add_argument("--no-time-filter", action="store_true", help="Include all timestamps in log files")
    parser.add_argument("-o", "--output", choices=["table", "json", "csv"], default="table", help="Output format")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("-v", "--version", action="version", version=f"ecpp.sh {VERSION}")
    args = parser.parse_args()

    if args.create:
        matches = find_mail_creation(args.create, args.cpanel_log_dir)
        if args.output == "json":
            print(json.dumps(matches, indent=2))
        else:
            for m in matches:
                print(f"[{m['file']}] {m['entry']}")
            if not matches:
                print(f"No creation record found for {args.create}")
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    stats = analyze_logs(args)
    if args.output == "json":
        print(json.dumps(stats, indent=2))
    elif args.output == "csv":
        render_csv(stats)
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        render_table(stats, Colors(enabled=use_color))


if __name__ == "__main__":
    main()
EOF

python3 -c "$PY_SCRIPT" "$@"
