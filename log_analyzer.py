#!/usr/bin/env python3
"""
log_analyzer.py — Simple security log analyzer

Features:
- Reads line-based logs (Windows Event exports, firewall logs, auth logs)
- OR reads Windows EVTX logs directly (e.g. Security.evtx)
- Detects failed logons and firewall blocks using regex patterns or Event IDs
- Flags suspicious IPs with many failed logons
- Detects account lockouts and "failed-then-success" patterns
- Collects EventData fields (SourceAddress, DestAddress, SourcePort, DestPort, Application, etc.)
- Writes alerts to CSV and prints a summary to the console

Usage examples:
    python log_analyzer.py --log-file security_export.txt --alerts alerts.csv
    python log_analyzer.py --log-file "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx" --alerts alerts.csv
"""

import argparse
import csv
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import os
import sys

# --- Optional imports for EVTX ----------------------------------------------

EVTX_AVAILABLE = False
try:
    import Evtx.Evtx as evtx
    import xml.etree.ElementTree as ET
    EVTX_AVAILABLE = True
except Exception:
    # We'll warn later only if user actually gives us a .evtx file
    EVTX_AVAILABLE = False

# --- Regex patterns (TEXT logs) ---------------------------------------------

# Common patterns for failed authentication in various logs (text mode)
FAILED_LOGIN_PATTERNS = [
    re.compile(r"failed login", re.IGNORECASE),
    re.compile(r"failure audit", re.IGNORECASE),
    re.compile(r"authentication failure", re.IGNORECASE),
    re.compile(r"invalid user", re.IGNORECASE),
    re.compile(r"Event ID:\s*4625", re.IGNORECASE),  # Windows failed logon
    re.compile(r"\bLOGIN FAILED\b", re.IGNORECASE),
]

# Simple firewall "blocked/denied" patterns (text mode)
FIREWALL_BLOCK_PATTERNS = [
    re.compile(r"\bblocked\b", re.IGNORECASE),
    re.compile(r"\bdenied\b", re.IGNORECASE),
    re.compile(r"\bdropped\b", re.IGNORECASE),
]

# IP address detection (IPv4 only for TEXT logs)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Very simple timestamp patterns (TEXT logs, you can extend)
TIMESTAMP_REGEXES = [
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),  # 2025-11-22 13:45:12
    re.compile(r"(?P<ts>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})"),  # 22/11/2025 13:45:12 / 11/22/2025 13:45:12
]

# Username extraction (best effort, TEXT logs)
USERNAME_PATTERNS = [
    re.compile(r"user(?:name)?\s*[:=]\s*(?P<user>[^\s\\]+)", re.IGNORECASE),
    re.compile(r"Account Name:\s*(?P<user>\S+)", re.IGNORECASE),
]

# --- Dynamic event mapping (EVTX) -------------------------------------------

EVENT_MAP: Dict[int, str] = {
    4625: "failed_login",
    4624: "successful_login",
    4740: "account_lockout",
    5156: "firewall_block",  # Windows Filtering Platform (firewall)
    4794: "password_change",  # DSRM / other password change events
    # Easy to extend:
    # 4769: "kerberos_ticket_request",
    # 4776: "ntlm_validation_failure",
    # 4648: "explicit_credentials_logon",
}


@dataclass
class LogEvent:
    timestamp: Optional[datetime]
    ip: Optional[str]
    username: Optional[str]
    event_type: str  # "failed_login", "successful_login", "account_lockout", "firewall_block", etc.
    raw_line: str    # For TEXT logs or short summary for EVTX
    data: Dict[str, Any]  # All EventData fields for EVTX (SourceAddress, DestPort, Application, etc.)


@dataclass
class Alert:
    timestamp: Optional[datetime]
    severity: str
    event_type: str
    source_ip: Optional[str]
    username: Optional[str]
    details: str
    source_port: Optional[str] = None
    dest_port: Optional[str] = None
    application: Optional[str] = None


# --- Helper functions: TEXT LOGS -------------------------------------------


def parse_timestamp(line: str) -> Optional[datetime]:
    """Try to extract a timestamp from a log line using a few common formats."""
    for rx in TIMESTAMP_REGEXES:
        m = rx.search(line)
        if not m:
            continue
        ts_text = m.group("ts")
        for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
            try:
                return datetime.strptime(ts_text, fmt)
            except ValueError:
                continue
    return None


def extract_ip(line: str) -> Optional[str]:
    """Extract the first IPv4 address from a log line, if any."""
    m = IP_REGEX.search(line)
    if not m:
        return None
    ip_str = m.group(0)
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        return None


def extract_username(line: str) -> Optional[str]:
    """Best-effort extraction of username from a line."""
    for rx in USERNAME_PATTERNS:
        m = rx.search(line)
        if m:
            return m.group("user")
    return None


# --- Core analyzer ----------------------------------------------------------


class LogAnalyzer:
    def __init__(self, fail_threshold: int = 5):
        """
        :param fail_threshold: number of failed logons per IP/user to trigger an alert
        """
        self.fail_threshold = fail_threshold
        self.events: List[LogEvent] = []

    # unified way to add events (used by both TEXT + EVTX paths)
    def add_event(
        self,
        event_type: str,
        timestamp: Optional[datetime],
        ip: Optional[str],
        username: Optional[str],
        raw: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.events.append(
            LogEvent(
                timestamp=timestamp,
                ip=ip,
                username=username,
                event_type=event_type,
                raw_line=raw,
                data=data or {},
            )
        )

    # TEXT mode
    def process_line(self, line: str) -> None:
        line = line.rstrip("\n")

        is_failed_login = any(p.search(line) for p in FAILED_LOGIN_PATTERNS)
        is_firewall_block = any(p.search(line) for p in FIREWALL_BLOCK_PATTERNS)

        if not (is_failed_login or is_firewall_block):
            return  # not interesting

        ts = parse_timestamp(line)
        ip = extract_ip(line)
        username = extract_username(line)

        if is_failed_login:
            event_type = "failed_login"
        elif is_firewall_block:
            event_type = "firewall_block"
        else:
            event_type = "unknown"

        self.add_event(event_type, ts, ip, username, line, {})

    def analyze(self) -> List[Alert]:
        """Aggregate events and produce alerts."""
        alerts: List[Alert] = []

        # Separate different event types for easier analysis
        failed_events = [e for e in self.events if e.event_type == "failed_login"]
        success_events = [e for e in self.events if e.event_type == "successful_login"]
        lockout_events = [e for e in self.events if e.event_type == "account_lockout"]
        password_change_events = [e for e in self.events if e.event_type == "password_change"]

        # Count failed logins per IP and per username
        ip_fail_counts: Counter[str] = Counter()
        user_fail_counts: Counter[str] = Counter()
        ip_last_ts: Dict[str, datetime] = {}
        user_last_ts: Dict[str, datetime] = {}

        for ev in failed_events:
            if ev.ip:
                ip_fail_counts[ev.ip] += 1
                if ev.timestamp:
                    prev = ip_last_ts.get(ev.ip)
                    if prev is None or ev.timestamp > prev:
                        ip_last_ts[ev.ip] = ev.timestamp

            if ev.username:
                user_fail_counts[ev.username] += 1
                if ev.timestamp:
                    prev = user_last_ts.get(ev.username)
                    if prev is None or ev.timestamp > prev:
                        user_last_ts[ev.username] = ev.timestamp

        # Alerts for IPs with many failed logins (possible brute force)
        for ip_str, count in ip_fail_counts.items():
            if count >= self.fail_threshold:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private:
                        severity = "MEDIUM"
                    else:
                        severity = "HIGH"
                except ValueError:
                    severity = "MEDIUM"

                details = f"{count} failed login attempts from IP {ip_str}"
                ts = ip_last_ts.get(ip_str)
                alerts.append(
                    Alert(
                        timestamp=ts,
                        severity=severity,
                        event_type="brute_force_suspected",
                        source_ip=ip_str,
                        username=None,
                        details=details,
                    )
                )

        # Alerts for users with many failed logins (possible targeted account)
        for user, count in user_fail_counts.items():
            if count >= self.fail_threshold:
                details = f"{count} failed login attempts for user '{user}'"
                ts = user_last_ts.get(user)
                alerts.append(
                    Alert(
                        timestamp=ts,
                        severity="MEDIUM",
                        event_type="account_targeted",
                        source_ip=None,
                        username=user,
                        details=details,
                    )
                )

        # Alerts for explicit account lockouts (EventID 4740)
        for ev in lockout_events:
            details = f"Account locked out: user='{ev.username or '-'}'"
            alerts.append(
                Alert(
                    timestamp=ev.timestamp,
                    severity="HIGH",
                    event_type="account_lockout",
                    source_ip=ev.ip,
                    username=ev.username,
                    details=details,
                )
            )

        # Alerts for password change events (e.g. EventID 4794 - DSRM password change)
        for ev in password_change_events:
            # Try to enrich with account info from EVTX fields
            account_name = (
                ev.data.get("AccountName")
                or ev.data.get("SubjectUserName")
                or ev.username
            )
            details = "Password change event detected"
            if account_name:
                details += f" for account '{account_name}'"

            alerts.append(
                Alert(
                    timestamp=ev.timestamp,
                    severity="HIGH",  # changing sensitive passwords is a high-value event
                    event_type="password_change",
                    source_ip=ev.ip,
                    username=account_name,
                    details=details,
                )
            )

        # Correlate: multiple failures followed by success (possible password guessing)
        combos: Dict[tuple, List[LogEvent]] = {}
        for ev in failed_events + success_events:
            key = (ev.ip, ev.username)
            combos.setdefault(key, []).append(ev)

        for (ip, user), evts in combos.items():
            if not ip or not user:
                continue

            evts = [e for e in evts if e.timestamp is not None]
            if len(evts) < 2:
                continue
            evts.sort(key=lambda e: e.timestamp)

            fail_streak = 0
            last_fail_time: Optional[datetime] = None

            for e in evts:
                if e.event_type == "failed_login":
                    fail_streak += 1
                    last_fail_time = e.timestamp
                elif e.event_type == "successful_login" and last_fail_time is not None:
                    # Success after >=3 fails within 10 minutes -> suspicious
                    if fail_streak >= 3 and e.timestamp - last_fail_time <= timedelta(minutes=10):
                        details = (
                            f"{fail_streak} failed logons from IP {ip} for user '{user}' "
                            f"followed by a successful logon within 10 minutes"
                        )
                        alerts.append(
                            Alert(
                                timestamp=e.timestamp,
                                severity="HIGH",
                                event_type="possible_compromise",
                                source_ip=ip,
                                username=user,
                                details=details,
                            )
                        )
                        fail_streak = 0
                        last_fail_time = None
                    else:
                        fail_streak = 0
                        last_fail_time = None

        # Direct alerts for firewall blocks (EVTX 5156 or TEXT logs)
        for ev in self.events:
            if ev.event_type == "firewall_block":
                # Try to pull richer context from ev.data (EVTX)
                src_addr = ev.data.get("SourceAddress") or ev.ip
                dest_addr = ev.data.get("DestAddress")
                src_port = ev.data.get("SourcePort")
                dest_port = ev.data.get("DestPort")
                app = ev.data.get("Application")

                # Build a human-readable detail string
                details_parts = []
                if src_addr:
                    details_parts.append(f"from {src_addr}")
                if dest_addr:
                    details_parts.append(f"to {dest_addr}")
                if src_port or dest_port:
                    details_parts.append(
                        f"ports {src_port or '?'}->{dest_port or '?'}"
                    )
                if app:
                    details_parts.append(f"app={app}")

                if details_parts:
                    detail_text = "Firewall blocked traffic " + ", ".join(details_parts)
                else:
                    detail_text = f"Firewall blocked traffic. Line: {ev.raw_line[:120]}..."

                alerts.append(
                    Alert(
                        timestamp=ev.timestamp,
                        severity="LOW",
                        event_type="firewall_block",
                        source_ip=src_addr,
                        username=ev.username,
                        details=detail_text,
                        source_port=src_port,
                        dest_port=dest_port,
                        application=app,
                    )
                )

        return alerts



# --- EVTX processing --------------------------------------------------------


def process_evtx_file(path: str, analyzer: LogAnalyzer, max_events: int) -> None:
    """
    Process a Windows EVTX file (e.g. Security.evtx or attack samples).
    Focus: Security log, especially EventIDs we mapped in EVENT_MAP.
    Reads up to max_events records.
    """
    if not EVTX_AVAILABLE:
        print(
            "[!] .evtx file provided, but python-evtx is not installed.\n"
            "    Install it with: pip install python-evtx",
            file=sys.stderr,
        )
        sys.exit(1)

    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"

    count = 0
    with evtx.Evtx(path) as log:
        for record in log.records():
            if count >= max_events:
                print(f"[i] Reached max_events limit ({max_events}), stopping EVTX read.")
                break

            count += 1
            if count % 10000 == 0:
                print(f"[i] Processed {count} EVTX records...")

            try:
                xml = record.xml()
                root = ET.fromstring(xml)

                system = root.find(f"{ns}System")
                if system is None:
                    continue

                event_id_el = system.find(f"{ns}EventID")
                if event_id_el is None or not event_id_el.text:
                    continue

                event_id = int(event_id_el.text)

                event_type = EVENT_MAP.get(event_id)
                if not event_type:
                    # Not mapped / not interesting for now
                    continue

                # TimeCreated/@SystemTime is UTC ISO string
                time_created_el = system.find(f"{ns}TimeCreated")
                ts: Optional[datetime] = None
                if time_created_el is not None and "SystemTime" in time_created_el.attrib:
                    ts_raw = time_created_el.attrib["SystemTime"]
                    try:
                        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).replace(tzinfo=None)
                    except ValueError:
                        ts = None

                event_data_el = root.find(f"{ns}EventData")
                event_fields: Dict[str, Any] = {}
                if event_data_el is not None:
                    for data in event_data_el.findall(f"{ns}Data"):
                        name = data.attrib.get("Name", "")
                        val = (data.text or "").strip()
                        if name:
                            event_fields[name] = val

                # Derive username
                username = (
                    event_fields.get("TargetUserName")
                    or event_fields.get("AccountName")
                    or event_fields.get("SubjectUserName")
                    or None
                )

                # Derive IP differently for security vs firewall events
                ip: Optional[str] = None
                if event_type in ("failed_login", "successful_login", "account_lockout"):
                    ip_candidate = event_fields.get("IpAddress") or event_fields.get("ClientAddress")
                elif event_type == "firewall_block":
                    ip_candidate = event_fields.get("SourceAddress") or event_fields.get("DestAddress")
                else:
                    ip_candidate = None

                if ip_candidate:
                    try:
                        # ipaddress supports IPv4 and IPv6 (e.g. ff02::1:2)
                        ipaddress.ip_address(ip_candidate)
                        ip = ip_candidate
                    except ValueError:
                        ip = None

                raw_short = f"EventID={event_id}, User={username}, IP={ip}"

                analyzer.add_event(
                    event_type=event_type,
                    timestamp=ts,
                    ip=ip,
                    username=username,
                    raw=raw_short,
                    data=event_fields,
                )

            except Exception:
                # Don't let one bad record kill the whole run
                continue

    print(f"[+] Finished reading {count} EVTX records.")


# --- I/O helpers ------------------------------------------------------------


def write_alerts_csv(alerts: List[Alert], path: str) -> None:
    """Write alerts to CSV."""
    fieldnames = [
        "timestamp",
        "severity",
        "event_type",
        "source_ip",
        "username",
        "details",
        "source_port",
        "dest_port",
        "application",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            row: Dict[str, Any] = {
                "timestamp": alert.timestamp.isoformat(sep=" ") if alert.timestamp else "",
                "severity": alert.severity,
                "event_type": alert.event_type,
                "source_ip": alert.source_ip or "",
                "username": alert.username or "",
                "details": alert.details,
                "source_port": alert.source_port or "",
                "dest_port": alert.dest_port or "",
                "application": alert.application or "",
            }
            writer.writerow(row)


def print_failed_login_summary(events: List[LogEvent]) -> None:
    """Print a small summary of failed logon activity."""
    failed = [e for e in events if e.event_type == "failed_login"]

    if not failed:
        print("[i] No failed logon events found.")
        return

    print(f"[i] Failed logon events: {len(failed)}")

    ip_counts = Counter(e.ip for e in failed if e.ip)
    if ip_counts:
        print("[i] Top source IPs:")
        for ip, count in ip_counts.most_common(5):
            print(f"    {ip:>15}  -> {count} attempts")

    user_counts = Counter(e.username for e in failed if e.username)
    if user_counts:
        print("[i] Top targeted accounts:")
        for user, count in user_counts.most_common(5):
            print(f"    {user:>20}  -> {count} attempts")

    print("[i] Recent failed logons:")
    for e in failed[-5:]:
        ts = e.timestamp.isoformat(sep=" ") if e.timestamp else "N/A"
        print(
            f"    {ts} | IP={e.ip or '-':>15} | user={e.username or '-':>15} | {e.raw_line}"
        )


def write_failed_logins_csv(events: List[LogEvent], path: str) -> None:
    """Export ALL failed login events to CSV (even if below alert threshold)."""
    failed = [e for e in events if e.event_type == "failed_login"]
    fieldnames = ["timestamp", "ip", "username", "raw_line"]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in failed:
            writer.writerow(
                {
                    "timestamp": e.timestamp.isoformat(sep=" ") if e.timestamp else "",
                    "ip": e.ip or "",
                    "username": e.username or "",
                    "raw_line": e.raw_line,
                }
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple security log analyzer")
    parser.add_argument(
        "--log-file",
        required=True,
        help="Path to the log file to analyze (text-based or .evtx).",
    )
    parser.add_argument(
        "--alerts",
        default="alerts.csv",
        help="Path for the output CSV file with alerts (default: alerts.csv).",
    )
    parser.add_argument(
        "--fail-threshold",
        type=int,
        default=5,
        help="Number of failed login events per IP/username to trigger an alert (default: 5).",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=50000,
        help="Maximum number of events to read from EVTX (default: 50000).",
    )
    parser.add_argument(
        "--failed-logins-csv",
        help="Optional path to export all failed login events to CSV.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    log_path = args.log_file

    if not os.path.exists(log_path):
        print(f"[!] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    analyzer = LogAnalyzer(fail_threshold=args.fail_threshold)

    if log_path.lower().endswith(".evtx"):
        print(f"[+] Reading EVTX log: {log_path}")
        process_evtx_file(log_path, analyzer, args.max_events)
    else:
        print(f"[+] Reading text log: {log_path}")
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                analyzer.process_line(line)

    alerts = analyzer.analyze()
    write_alerts_csv(alerts, args.alerts)

    print_failed_login_summary(analyzer.events)

    if args.failed_logins_csv:
        write_failed_logins_csv(analyzer.events, args.failed_logins_csv)
        print(f"[+] Wrote failed login events to {args.failed_logins_csv}")

    print(f"[+] Processed events: {len(analyzer.events)}")
    print(f"[+] Generated alerts: {len(alerts)}")
    if alerts:
        print("\nSample alerts:")
        for alert in alerts[:10]:
            ts = alert.timestamp.isoformat(sep=" ") if alert.timestamp else "N/A"
            print(
                f"  - [{alert.severity}] {alert.event_type} | "
                f"IP={alert.source_ip or '-'} | user={alert.username or '-'} | "
                f"time={ts} | {alert.details}"
            )


if __name__ == "__main__":
    main()
