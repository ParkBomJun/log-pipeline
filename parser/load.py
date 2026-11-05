#!/usr/bin/env python3
"""파싱 결과를 SQLite DB에 적재.

사용법:
    python3 load.py ../sample_logs/auth.log ../sample_logs/firewall.log

동작:
  1. 기존 db/pipeline.db를 지우고 schema.sql로 새 DB 생성
  2. 호스트는 hosts 테이블에 upsert 후 FK로 연결
  3. 이벤트 일괄 insert (executemany 배치)
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from parser import parse_file  # noqa: E402

ROOT = Path(__file__).parent.parent
DB_PATH = ROOT / "db" / "pipeline.db"
SCHEMA = ROOT / "db" / "schema.sql"

ROLE_HINT = {"web": "web", "db": "db", "bastion": "bastion"}


def guess_role(hostname: str) -> str | None:
    for key, role in ROLE_HINT.items():
        if hostname.startswith(key):
            return role
    return None


def get_or_create_host(cur, hostname: str, cache: dict) -> int:
    if hostname in cache:
        return cache[hostname]
    cur.execute("INSERT OR IGNORE INTO hosts (hostname, role) VALUES (?, ?)",
                (hostname, guess_role(hostname)))
    cur.execute("SELECT host_id FROM hosts WHERE hostname = ?", (hostname,))
    hid = cur.fetchone()[0]
    cache[hostname] = hid
    return hid


def init_db(conn: sqlite3.Connection) -> None:
    """schema.sql로 테이블·인덱스·기본 소스를 만든다."""
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))


def load_files(conn: sqlite3.Connection, paths: list[str]) -> int:
    """로그 파일들을 파싱해 events에 적재하고, 적재한 총 건수를 돌려준다."""
    cur = conn.cursor()
    cur.execute("SELECT source_name, source_id FROM log_sources")
    source_ids = dict(cur.fetchall())

    host_cache: dict[str, int] = {}
    total = 0
    for path in paths:
        batch = []
        for rec in parse_file(path):
            hid = get_or_create_host(cur, rec["hostname"], host_cache)
            batch.append((
                rec["ts"], hid, source_ids[rec["source"]],
                rec["event_type"], rec["username"], rec["src_ip"],
                rec["dst_ip"], rec["dst_port"], rec["proto"], rec["raw"],
            ))
        cur.executemany(
            """INSERT INTO events
               (ts, host_id, source_id, event_type, username,
                src_ip, dst_ip, dst_port, proto, raw)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", batch)
        total += len(batch)
        print(f"{path}: {len(batch)}건 적재")

    conn.commit()
    return total


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("사용법: python3 load.py <로그파일> [로그파일...]")

    # 매번 DB를 지우고 처음부터 다시 적재한다.
    # 같은 로그로 여러 번 실행해도 중복 없이 같은 결과가 나온다(전체 재적재 방식).
    if DB_PATH.exists():
        DB_PATH.unlink()

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    total = load_files(conn, sys.argv[1:])
    conn.close()
    print(f"완료: 총 {total}건 -> {DB_PATH}")


if __name__ == "__main__":
    main()
