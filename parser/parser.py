#!/usr/bin/env python3
"""로그 파서: 비정형 로그 라인 → 구조화 dict.

지원 포맷:
  1. auth.log (RFC3164 스타일 syslog): SSH 인증 성공/실패, 세션 종료, sudo
  2. iptables 방화벽 로그 (FW-DROP prefix)

설계 노트:
  - 패턴별 정규식을 리스트로 관리해 새 로그 타입 추가가 쉬운 구조
  - 파싱 실패 라인은 버리지 않고 event_type='unparsed'로 보존 (SIEM 관행)
"""
import re
from datetime import datetime

# syslog 헤더: "Jul  4 13:22:01 web-01 sshd[1234]:" 형태
SYSLOG_HEAD = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-\/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

PATTERNS = [
    ("auth_fail", re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<src_ip>[\d.]+) port \d+")),
    ("auth_ok", re.compile(
        r"Accepted \w+ for (?P<user>\S+) from (?P<src_ip>[\d.]+) port \d+")),
    ("session_close", re.compile(
        r"session closed for user (?P<user>\S+)")),
    ("sudo", re.compile(
        r"^(?P<user>\S+) : TTY=.*COMMAND=(?P<cmd>.*)$")),
    ("fw_drop", re.compile(
        r"FW-DROP: .*SRC=(?P<src_ip>[\d.]+) DST=(?P<dst_ip>[\d.]+) "
        r"PROTO=(?P<proto>\w+) SPT=\d+ DPT=(?P<dst_port>\d+)")),
]

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def _to_iso(mon: str, day: str, time_: str, year: int | None = None) -> str:
    """syslog 타임스탬프(연도 없음) → ISO8601. 연도는 현재 연도로 보정."""
    y = year or datetime.now().year
    return f"{y:04d}-{MONTHS[mon]:02d}-{int(day):02d}T{time_}"


def parse_line(line: str) -> dict | None:
    """한 줄 파싱. syslog 헤더가 아예 없으면 None."""
    line = line.rstrip("\n")
    head = SYSLOG_HEAD.match(line)
    if not head:
        return None

    base = {
        "ts": _to_iso(head["mon"], head["day"], head["time"]),
        "hostname": head["host"],
        "event_type": "unparsed",
        "username": None, "src_ip": None, "dst_ip": None,
        "dst_port": None, "proto": None,
        "source": "auth",   # 기본값, fw_drop이면 아래서 교체
        "raw": line,
    }

    msg = head["msg"]
    for etype, pat in PATTERNS:
        m = pat.search(msg)
        if m:
            base["event_type"] = etype
            g = m.groupdict()
            base["username"] = g.get("user")
            base["src_ip"] = g.get("src_ip")
            base["dst_ip"] = g.get("dst_ip")
            base["dst_port"] = int(g["dst_port"]) if g.get("dst_port") else None
            base["proto"] = g.get("proto")
            if etype == "fw_drop":
                base["source"] = "firewall"
            break
    return base


def parse_file(path: str):
    """파일 전체 파싱 제너레이터. (라인 단위 스트리밍 — 대용량 대비)"""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_line(line)
            if rec:
                yield rec


if __name__ == "__main__":
    import sys, json
    for p in sys.argv[1:]:
        ok = bad = 0
        for rec in parse_file(p):
            if rec["event_type"] == "unparsed":
                bad += 1
            else:
                ok += 1
        print(f"{p}: 파싱 성공 {ok} / 미분류 {bad}")
