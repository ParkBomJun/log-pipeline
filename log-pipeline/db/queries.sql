-- 분석 쿼리 세트 v1
-- 목적: 정규화 스키마 위에서 조인·집계·서브쿼리를 실전 시나리오로 연습
-- 실행: sqlite3 pipeline.db < queries.sql  (또는 report/report.py 로 실행)

-- [Q1] 호스트별 로그인 실패 횟수 (2테이블 조인 + 집계)
SELECT h.hostname, h.role, COUNT(*) AS fail_count
FROM events e
JOIN hosts h ON h.host_id = e.host_id
WHERE e.event_type = 'auth_fail'
GROUP BY h.hostname, h.role
ORDER BY fail_count DESC;

-- [Q2] 브루트포스 의심 IP: 실패 10회 이상 (조인 + HAVING)
--      가장 단순한 형태. 전체 기간 누적이라 오탐 가능성이 있다(아래 Q2b가 개선형).
SELECT e.src_ip,
       COUNT(*)                    AS fail_count,
       COUNT(DISTINCT e.username)  AS tried_users,
       COUNT(DISTINCT h.hostname)  AS tried_hosts,
       MIN(e.ts) AS first_attempt, MAX(e.ts) AS last_attempt
FROM events e
JOIN hosts h ON h.host_id = e.host_id
WHERE e.event_type = 'auth_fail'
GROUP BY e.src_ip
HAVING COUNT(*) >= 10
ORDER BY fail_count DESC;

-- [Q2b] 시간 창 기반 브루트포스: 5분 내 5회 이상 실패한 (IP, 5분 버킷) 조합
--       실제 SIEM 탐지 룰에 가까운 형태. "짧은 시간에 몰아서"를 잡아내
--       하루 종일 띄엄띄엄 실패한 정상 사용자의 오탐을 줄인다.
--       strftime으로 타임스탬프를 5분 단위 버킷으로 잘라 그룹화한다.
SELECT e.src_ip,
       strftime('%Y-%m-%d %H:', e.ts) ||
         printf('%02d', (CAST(strftime('%M', e.ts) AS INTEGER) / 5) * 5)
                                   AS window_5min,
       COUNT(*)                    AS fails_in_window,
       COUNT(DISTINCT e.username)  AS tried_users
FROM events e
WHERE e.event_type = 'auth_fail'
GROUP BY e.src_ip, window_5min
HAVING COUNT(*) >= 5
ORDER BY fails_in_window DESC
LIMIT 20;

-- [Q3] 짧은 시간 안에 다수 실패 후 성공한 로그인 - 침해 의심 시나리오 (상관 서브쿼리)
--      주의: 단순 셀프 조인(fail × 이후 모든 success)은 카티전 곱으로 폭발한다.
--      성공 이벤트 기준으로 "직전 10분 동안 동일 IP의 실패 횟수"를 세는 방식이 정확.
SELECT s.src_ip,
       s.username AS succeeded_as,
       s.ts       AS success_time,
       (SELECT COUNT(*) FROM events f
         WHERE f.src_ip = s.src_ip
           AND f.event_type = 'auth_fail'
           AND datetime(f.ts) >= datetime(s.ts, '-10 minutes')
           AND datetime(f.ts) < datetime(s.ts)) AS fails_before_10min
FROM events s
WHERE s.event_type = 'auth_ok'
  AND (SELECT COUNT(*) FROM events f
        WHERE f.src_ip = s.src_ip
          AND f.event_type = 'auth_fail'
          AND datetime(f.ts) >= datetime(s.ts, '-10 minutes')
          AND datetime(f.ts) < datetime(s.ts)) >= 5
ORDER BY fails_before_10min DESC
LIMIT 20;

-- [Q4] 방화벽 차단 상위 출발지 × 인증 실패 교차 (3테이블 상관분석)
--      방화벽에서도 걸리고 SSH 실패도 낸 IP = 명확한 공격자
SELECT fw.src_ip,
       fw.drop_count,
       au.fail_count
FROM (
    SELECT src_ip, COUNT(*) AS drop_count
    FROM events WHERE event_type = 'fw_drop'
    GROUP BY src_ip
) fw
JOIN (
    SELECT src_ip, COUNT(*) AS fail_count
    FROM events WHERE event_type = 'auth_fail'
    GROUP BY src_ip
) au ON au.src_ip = fw.src_ip
ORDER BY fw.drop_count + au.fail_count DESC;

-- [Q5] 소스별/타입별 이벤트 분포 (조인 + 전체 현황 파악)
SELECT s.source_name, e.event_type, COUNT(*) AS cnt
FROM events e
JOIN log_sources s ON s.source_id = e.source_id
GROUP BY s.source_name, e.event_type
ORDER BY s.source_name, cnt DESC;
