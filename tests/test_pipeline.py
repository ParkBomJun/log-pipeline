"""파서·생성기·탐지 쿼리 테스트 (표준 라이브러리 unittest만 사용).

실행: python3 -m unittest discover -s tests -v   (저장소 루트에서)
"""
import random
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for sub in ("parser", "collector", "report"):
    sys.path.insert(0, str(ROOT / sub))

from parser import parse_line  # noqa: E402
from load import init_db, load_files  # noqa: E402
from generate_sample_logs import render_auth_log  # noqa: E402
from report import QUERIES, split_queries  # noqa: E402


class ParseLineTest(unittest.TestCase):
    def test_auth_fail_invalid_user(self):
        rec = parse_line("Nov  5 09:01:02 bastion sshd[1234]: Failed password for "
                         "invalid user admin from 203.0.113.45 port 50001 ssh2")
        self.assertEqual(rec["event_type"], "auth_fail")
        self.assertEqual(rec["username"], "admin")
        self.assertEqual(rec["src_ip"], "203.0.113.45")
        self.assertEqual(rec["hostname"], "bastion")
        self.assertTrue(rec["ts"].endswith("-11-05T09:01:02"))

    def test_auth_ok(self):
        rec = parse_line("Nov  5 09:06:02 bastion sshd[4099]: Accepted password for "
                         "admin from 203.0.113.45 port 50099 ssh2")
        self.assertEqual(rec["event_type"], "auth_ok")
        self.assertEqual(rec["username"], "admin")

    def test_sudo(self):
        rec = parse_line("Nov  5 09:06:32 bastion sudo: admin : TTY=pts/0 ; "
                         "PWD=/home/admin ; USER=root ; COMMAND=/bin/bash")
        self.assertEqual(rec["event_type"], "sudo")
        self.assertEqual(rec["username"], "admin")

    def test_firewall_drop(self):
        rec = parse_line("Nov  5 09:10:00 web-01 kernel: FW-DROP: IN=eth0 OUT= "
                         "SRC=198.51.100.7 DST=10.0.1.20 PROTO=TCP SPT=40000 DPT=22")
        self.assertEqual(rec["event_type"], "fw_drop")
        self.assertEqual(rec["source"], "firewall")
        self.assertEqual(rec["dst_port"], 22)
        self.assertEqual(rec["dst_ip"], "10.0.1.20")

    def test_unknown_message_is_kept_as_unparsed(self):
        line = "Nov  5 09:11:00 db-01 cron[777]: (root) CMD (run-parts /etc/cron.hourly)"
        rec = parse_line(line)
        self.assertEqual(rec["event_type"], "unparsed")
        self.assertEqual(rec["raw"], line)  # 원본 보존

    def test_line_without_syslog_header_is_skipped(self):
        self.assertIsNone(parse_line("this is not a syslog line"))


class GeneratorOrderTest(unittest.TestCase):
    def test_month_boundary_keeps_time_order(self):
        # 기준 시각이 11월 1일 새벽이면 로그가 10월 말~11월 1일에 걸친다.
        # 문자열 정렬이면 "Nov"가 "Oct"보다 앞에 와서 순서가 뒤집힌다.
        random.seed(7)
        lines = render_auth_log(datetime(2026, 11, 1, 0, 30), 200)
        months = [ln[:3] for ln in lines]
        self.assertIn("Oct", months)
        self.assertIn("Nov", months)
        last_oct = max(i for i, m in enumerate(months) if m == "Oct")
        first_nov = months.index("Nov")
        self.assertLess(last_oct, first_nov)


class DetectionQueryTest(unittest.TestCase):
    """생성기가 심은 '브루트포스 후 로그인 성공' 시나리오를 Q3가 잡는지 확인."""

    def test_q3_detects_injected_account_takeover(self):
        random.seed(42)
        lines = render_auth_log(datetime(2026, 11, 5, 12, 0), 300)
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "auth.log"
            log.write_text("\n".join(lines) + "\n", encoding="utf-8")

            conn = sqlite3.connect(":memory:")
            init_db(conn)
            load_files(conn, [str(log)])

            queries = dict(split_queries(QUERIES.read_text(encoding="utf-8")))
            q3 = next(sql for title, sql in queries.items() if title.startswith("[Q3]"))
            rows = conn.execute(q3.strip().rstrip(";")).fetchall()
            conn.close()

        hits = {(ip, user) for ip, user, _ts, fails in rows if fails >= 20}
        self.assertIn(("203.0.113.45", "admin"), hits)


if __name__ == "__main__":
    unittest.main()
