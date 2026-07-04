# log-pipeline

리눅스 시스템 로그(auth.log)와 방화벽 로그를 수집·정규화하여 SQL로 분석하는 미니 로그 파이프라인.
SIEM 솔루션 엔지니어링의 핵심 흐름(수집 → 정규화 → 저장 → 상관분석)을 축소 구현한 학습·포트폴리오 프로젝트입니다.

이 저장소의 로그는 모두 개발용 샘플 데이터이며, 실제 고객사/운영 환경 로그는 포함하지 않습니다.

## 아키텍처

```
[수집]      auth.log, firewall.log  (개발 단계: collector/의 샘플 생성기)
   ↓
[정규화]    parser/parser.py  — 정규식 기반 파싱, 미분류 라인도 보존
   ↓
[저장]      db/pipeline.db  — 정규화 3테이블 (hosts / log_sources / events)
   ↓
[분석]      db/queries.sql  — 조인·집계·상관 서브쿼리 6종
   ↓
[리포트]    report/report.py  — 텍스트 리포트 출력
```

## 빠른 시작 (WSL Ubuntu 기준)

```bash
# 1. 샘플 로그 생성 (개발용)
cd collector && python3 generate_sample_logs.py --lines 800

# 2. 파싱 검증
cd ../parser && python3 parser.py ../sample_logs/auth.log ../sample_logs/firewall.log

# 3. DB 적재 (스키마 자동 생성)
python3 load.py ../sample_logs/auth.log ../sample_logs/firewall.log

# 4. 분석 리포트
cd ../report && python3 report.py
```

외부 의존성 없음 — Python 3.10+ 표준 라이브러리만 사용.

## 분석 쿼리 (db/queries.sql)

| # | 내용 | SQL 기법 |
|---|---|---|
| Q1 | 호스트별 로그인 실패 횟수 | JOIN + GROUP BY |
| Q2 | 브루트포스 의심 IP (실패 10회 이상) | JOIN + HAVING + DISTINCT 집계 |
| Q2b | 5분 시간 창 기준 브루트포스 의심 IP | 시간 버킷 + GROUP BY + HAVING |
| Q3 | 직전 10분 다수 실패 후 성공한 로그인 (침해 의심) | 상관 서브쿼리 |
| Q4 | 방화벽 차단 × 인증 실패 교차 IP | 파생 테이블 간 JOIN |
| Q5 | 소스·타입별 이벤트 분포 | JOIN + 다중 GROUP BY |

## 설계 노트

- **정규화 스키마**: 이벤트를 단일 테이블에 넣지 않고 호스트/소스를 분리 —
  조회 시 조인이 자연스럽게 필요한 구조로 SQL 실전 감각 확보
- **원본 보존**: 파싱 실패 라인도 `event_type='unparsed'`로 저장 (SIEM 증적 관행)
- **Q3 교훈**: 최초 구현은 fail × success 셀프 조인이었으나 카티전 곱으로 결과 폭발 →
  성공 이벤트 기준 직전 10분 실패 횟수를 세는 상관 서브쿼리로 재설계.
  조인 조건과 시간 창 설계의 중요성을 보여주는 사례
- **스트리밍 파싱**: 파일 전체를 메모리에 올리지 않는 제너레이터 구조 (대용량 대비)

## 로드맵

- [x] Sprint 1 — 파서 + 스키마 + 조인 쿼리 + 리포트 (현재)
- [ ] Sprint 2 — 실제 WSL /var/log/auth.log 수집 연결, PostgreSQL 이관, rsyslog 설정
- [ ] Sprint 3 — LLM 요약 계층 (일일 리포트 자연어 요약, 이상 패턴 해설), 설계 문서화
