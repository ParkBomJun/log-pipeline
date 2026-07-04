#!/usr/bin/env python3
"""분석 리포트 생성: queries.sql의 쿼리를 실행해 텍스트 리포트 출력.

사용법:
    python3 report.py            # 콘솔 출력
    python3 report.py > daily_report.txt
"""
import signal
import sqlite3
from pathlib import Path

# head 등 파이프가 먼저 닫혀도 조용히 종료. Windows에는 SIGPIPE가 없다.
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

ROOT = Path(__file__).parent.parent
DB_PATH = ROOT / "db" / "pipeline.db"
QUERIES = ROOT / "db" / "queries.sql"


def split_queries(sql_text: str):
    """주석 헤더([Q1] 제목)와 쿼리 본문을 분리."""
    blocks = []
    title, buf = None, []
    for line in sql_text.splitlines():
        if line.startswith("-- [Q"):
            if title and buf:
                blocks.append((title, "\n".join(buf)))
            title, buf = line.lstrip("- ").strip(), []
        elif line.startswith("--"):
            continue
        else:
            buf.append(line)
    if title and buf:
        blocks.append((title, "\n".join(buf)))
    return blocks


def render_table(headers, rows, max_width=30) -> str:
    if not rows:
        return "  (결과 없음)\n"
    cols = [headers] + [[str(c)[:max_width] if c is not None else "-"
                         for c in r] for r in rows]
    widths = [max(len(row[i]) for row in cols) for i in range(len(headers))]
    lines = []
    for idx, row in enumerate(cols):
        lines.append("  " + " | ".join(c.ljust(w) for c, w in zip(row, widths)))
        if idx == 0:
            lines.append("  " + "-+-".join("-" * w for w in widths))
    return "\n".join(lines) + "\n"


def main() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    print("=" * 62)
    print(" 로그 파이프라인 분석 리포트")
    cur.execute("SELECT COUNT(*), MIN(ts), MAX(ts) FROM events")
    n, lo, hi = cur.fetchone()
    print(f" 총 이벤트: {n}건 / 기간: {lo} ~ {hi}")
    print("=" * 62)

    for title, sql in split_queries(QUERIES.read_text(encoding="utf-8")):
        sql = sql.strip().rstrip(";")
        if not sql:
            continue
        print(f"\n## {title}\n")
        cur.execute(sql)
        headers = [d[0] for d in cur.description]
        print(render_table(headers, cur.fetchall()))

    conn.close()


if __name__ == "__main__":
    main()
