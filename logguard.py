
#!/usr/bin/env python3
"""LogGuard - простой анализатор SSH-логов.

Ищет неудачные попытки входа (Failed password), считает топ атакующих
IP и помечает brute-force атаки по скользящему окну времени.

Только стандартная библиотека Python. Запуск:
    python logguard.py sample_auth.log
    python logguard.py sample_auth.log --window 5 --threshold 3 --csv report.csv
    python logguard.py sample_auth.log --json report.json
"""

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s+sshd
$$
(?P<pid>\d+)
$$
:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+) ssh2"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_file(path):
    """Возвращает список событий: (datetime, ip, user)."""
    events = []
    year = datetime.now().year
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LINE_RE.search(line)
            if not m:
                continue
            hh, mm, ss = m.group("time").split(":")
            ts = datetime(year, MONTHS[m.group("month")], int(m.group("day")),
                          int(hh), int(mm), int(ss))
            events.append((ts, m.group("ip"), m.group("user")))
    return events


def analyze(events, window_min, threshold):
    """Собирает статистику по IP и помечает brute-force."""
    stats = {}
    by_ip = defaultdict(list)
    for ts, ip, user in events:
        by_ip[ip].append((ts, user))

    for ip, evs in by_ip.items():
        evs.sort()
        users = {u for _, u in evs}
        first, last = evs[0][0], evs[-1][0]
        brute = False
        window = timedelta(minutes=window_min)
        for i, (ts, _) in enumerate(evs):
            count = sum(1 for t, _ in evs[i:] if t - ts <= window)
            if count >= threshold:
                brute = True
                break
        stats[ip] = {
            "fails": len(evs),
            "users": sorted(users),
            "first": first,
            "last": last,
            "brute": brute,
        }
    return stats


def save_report_json(stats, path):
    """Сохраняет отчёт в JSON-файл."""
    report = []
    for ip, s in sorted(stats.items(), key=lambda x: -x[1]["fails"]):
        report.append({
            "ip": ip,
            "failed_attempts": s["fails"],
            "users": s["users"],
            "first_seen": s["first"].isoformat(timespec="seconds"),
            "last_seen": s["last"].isoformat(timespec="seconds"),
            "brute_force": s["brute"],
        })

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    print(f"\n[+] JSON-отчёт сохранён: {path}")


def main():
    ap = argparse.ArgumentParser(description="SSH failed-login log analyzer")
    ap.add_argument("logfile", nargs="?", default="sample_auth.log")
    ap.add_argument("--window", type=int, default=10,
                    help="окно анализа в минутах (по умолчанию 10)")
    ap.add_argument("--threshold", type=int, default=5,
                    help="попыток в окне для brute-force (по умолчанию 5)")
    ap.add_argument("--csv", help="путь для сохранения отчёта CSV")
    ap.add_argument("--json", help="путь для сохранения отчёта JSON")
    args = ap.parse_args()

    try:
        events = parse_file(args.logfile)
    except FileNotFoundError:
        sys.exit(f"Ошибка: файл {args.logfile!r} не найден")

    if not events:
        print("Failed password не найдены.")
        return

    stats = analyze(events, args.window, args.threshold)

    print(f"\nLogGuard: {len(events)} failed-попыток, "
          f"{len(stats)} уникальных IP\n")
    header = f"{'IP':<18}{'Fails':>6}  {'Users':<30}{'Period':<30}Flag"
    print(header)
    print("-" * len(header))
    for ip, s in sorted(stats.items(), key=lambda x: -x[1]["fails"]):
        period = f"{s['first']:%H:%M} - {s['last']:%H:%M}"
        flag = "BRUTE-FORCE" if s["brute"] else ""
        print(f"{ip:<18}{s['fails']:>6}  {', '.join(s['users'])[:28]:<30}"
              f"{period:<30}{flag}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["ip", "failed_attempts", "users",
                        "first_seen", "last_seen", "brute_force"])
            for ip, s in sorted(stats.items(), key=lambda x: -x[1]["fails"]):
                w.writerow([ip, s["fails"], " ".join(s["users"]),
                            s["first"].isoformat(timespec="seconds"),
                            s["last"].isoformat(timespec="seconds"),
                            "yes" if s["brute"] else "no"])
        print(f"\nОтчёт сохранён: {args.csv}")

    if args.json:
        save_report_json(stats, args.json)


if __name__ == "__main__":
    main()