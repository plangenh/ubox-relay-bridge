#!/usr/bin/env python3
"""Offline check of tracked files; reports locations, never matched contents."""
import ipaddress
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
RULES = {
    "local user path": re.compile(r"/(?:Users|home)/[^/\s]+/"),
    "email address": re.compile(r"[\w.%+\-]+@[\w.\-]+\.[A-Za-z]{2,}"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "access token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})"),
    "private MCP webhook": re.compile(r"/api/" r"webhook/|\bmcp_[a-fA-F0-9]{20,}"),
}
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
FORBIDDEN = {
    ".h264", ".h265", ".hevc", ".mp4", ".mkv", ".ts", ".jpg", ".jpeg",
    ".png", ".pcap", ".pcapng", ".har", ".rdt", ".log", ".ipa", ".apk",
    ".dmg", ".exe", ".zip", ".bin",
}
issues = []
count = 0
for name in filter(None, FILES):
    path = ROOT / name
    parts = Path(name).parts
    if path.is_symlink():
        issues.append((name, 0, "symlink"))
        continue
    if (".storage" in parts or path.suffix.lower() in FORBIDDEN
            or path.name in {".env", "core.config_entries", "go2rtc.yaml", "configuration.yaml"}
            or path.name.startswith((".env.", "secrets.", "credentials"))
            or (path.suffix.lower() == ".m3u" and not name.endswith(".example.m3u"))):
        issues.append((name, 0, "private artifact/configuration"))
        continue
    if path.stat().st_size > 1_000_000:
        issues.append((name, 0, "unexpected large file"))
        continue
    try:
        data = path.read_text(encoding="utf-8")
    except UnicodeError:
        issues.append((name, 0, "non-text file"))
        continue
    count += 1
    for number, line in enumerate(data.splitlines(), 1):
        for label, pattern in RULES.items():
            if pattern.search(line):
                issues.append((name, number, label))
        for match in IPV4.finditer(line):
            try:
                ip = ipaddress.IPv4Address(match.group())
            except ipaddress.AddressValueError:
                continue
            a, b, _, _ = ip.packed
            if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 100 and 64 <= b <= 127) or (a == 169 and b == 254):
                issues.append((name, number, "private/VPN network address"))
if issues:
    for name, number, label in issues:
        print(f"{name}:{number}: {label}", file=sys.stderr)
    sys.exit(1)
print(f"Privacy check passed for {count} tracked text files. Manual review remains required.")
