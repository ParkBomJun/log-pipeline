-- 로그 파이프라인 스키마 v1 (SQLite / PostgreSQL 호환 의식해서 작성)
-- 설계 의도: 이벤트를 단일 테이블에 다 넣지 않고 호스트/소스를 분리해
--            조회 시 조인이 자연스럽게 필요한 정규화 구조로 만든다.

CREATE TABLE IF NOT EXISTS hosts (
    host_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname    TEXT NOT NULL UNIQUE,
    role        TEXT,                      -- web / db / bastion 등 (수동 태깅)
    first_seen  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS log_sources (
    source_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL UNIQUE,      -- 'auth' / 'firewall'
    description TEXT
);

CREATE TABLE IF NOT EXISTS events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,             -- ISO8601
    host_id     INTEGER NOT NULL REFERENCES hosts(host_id),
    source_id   INTEGER NOT NULL REFERENCES log_sources(source_id),
    event_type  TEXT NOT NULL,             -- auth_fail / auth_ok / session_close / sudo / fw_drop
    username    TEXT,                      -- 인증 이벤트일 때
    src_ip      TEXT,                      -- 원격지 IP
    dst_ip      TEXT,                      -- 방화벽 이벤트일 때
    dst_port    INTEGER,
    proto       TEXT,
    raw         TEXT NOT NULL              -- 원본 로그 라인 (증적 보존)
);

CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_host      ON events(host_id);

INSERT OR IGNORE INTO log_sources (source_name, description) VALUES
    ('auth',     'Linux 인증 로그 (/var/log/auth.log)'),
    ('firewall', 'iptables 방화벽 DROP 로그');
