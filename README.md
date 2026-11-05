# log-pipeline

[![CI](https://github.com/ParkBomJun/log-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/ParkBomJun/log-pipeline/actions/workflows/ci.yml)

리눅스 시스템 로그(auth.log)와 방화벽 로그를 수집·정규화하여 SQL로 분석하는 미니 로그 파이프라인.
SIEM 솔루션 엔지니어링의 핵심 흐름(수집 → 정규화 → 저장 → 상관분석)을 축소 구현한 학습·포트폴리오 프로젝트입니다.

이 저장소의 로그는 모두 개발용 샘플 데이터이며, 실제 고객사/운영 환경 로그는 포함하지 않습니다.

## 아키텍처

```
[수집]      auth.log, firewall.log  (개발 단계: collector/의 샘플 생성기)
   ↓
[정규화]    parser/parser.py  — 정규식 기반 파싱, 미분류 라인도 보존
   ↓
[저장]      db/pipeline.db  — 정규화 3테이블 (hosts / log_sources / events), 실행 시 생성
   ↓
[분석]      db/queries.sql  — 조인·집계·상관 서브쿼리 6종
   ↓
[리포트]    report/report.py  — 텍스트 리포트 출력
```

## 빠른 시작 (WSL Ubuntu 기준)

```bash
git clone https://github.com/ParkBomJun/log-pipeline.git
cd log-pipeline

# 1. 샘플 로그 생성 (개발용 — 저장소에 들어 있는 sample_logs/를 그대로 써도 됨)
cd collector && python3 generate_sample_logs.py --lines 800

# 2. 파싱 검증
cd ../parser && python3 parser.py ../sample_logs/auth.log ../sample_logs/firewall.log

# 3. DB 적재 (스키마 자동 생성, 실행할 때마다 처음부터 다시 적재)
python3 load.py ../sample_logs/auth.log ../sample_logs/firewall.log

# 4. 분석 리포트
cd ../report && python3 report.py
```

외부 의존성 없음 — Python 3.10+ 표준 라이브러리만 사용.

## 결과 예시

저장소의 `sample_logs/`(총 1,622건)로 돌린 리포트 일부.

**Q3 — 다수 실패 후 로그인 성공 (침해 의심)**

```
  src_ip       | succeeded_as | success_time        | fails_before_10min
  -------------+--------------+---------------------+-------------------
  203.0.113.45 | admin        | 2026-07-04T05:13:49 | 20
```

생성기가 심어 둔 "admin 계정 20회 연속 실패 → 같은 IP로 로그인 성공 → sudo" 흐름을 잡아낸다.

**Q2 vs Q2b — 누적 기준과 시간 창 기준의 차이**

- Q2(전체 기간 누적 10회 이상)는 공격 IP들과 함께 내부 IP `10.0.1.15`도 잡는다. 이틀 동안 띄엄띄엄 실패한 정상 사용자까지 걸리는 오탐이다.
- Q2b(5분 안에 5회 이상)에는 짧은 시간에 몰아친 `203.0.113.45`만 남는다.

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
- **재실행 안전**: `load.py`는 매번 DB를 지우고 처음부터 다시 적재한다. 같은 로그로
  여러 번 돌려도 중복 없이 같은 결과가 나온다 (전체 재적재 방식)

## 테스트

```bash
python3 -m unittest discover -s tests -v   # 저장소 루트에서
```

- 로그 종류별 파싱, 미분류 라인 원본 보존, syslog가 아닌 줄 건너뛰기
- 월이 바뀌는 구간(10월 말~11월 초)에서 샘플 로그가 시각순으로 나오는지
- 생성기가 심은 공격 시나리오를 Q3가 잡아내는지

GitHub Actions가 push·PR마다 테스트와 전체 파이프라인(생성 → 파싱 → 적재 → 리포트)을 Python 3.11, 3.13에서 돌린다.

## 알려진 한계

- **연도 추정**: syslog 타임스탬프에는 연도가 없어서 실행 시점의 연도를 붙인다. 12월 로그를 1월에 적재하면 연도가 1년 어긋난다.
- **고정 5분 칸**: Q2b는 시계 기준 5분 칸(00~05분, 05~10분 …)으로 자르기 때문에 칸 경계에 걸친 연속 공격이 둘로 나뉜다. 샘플 결과에서도 한 번의 연속 공격이 두 칸(15회, 6회)으로 나뉘어 나온다. 슬라이딩 윈도우로 바꾸는 것이 다음 개선 후보.
- **전체 재적재**: 실행마다 DB를 새로 만들어서 로그가 커지면 느려진다. 마지막으로 읽은 위치를 기억하는 증분 적재가 필요하다.

## 로드맵

- [x] Sprint 1 — 파서 + 스키마 + 조인 쿼리 + 리포트
- [ ] Sprint 2 — 실제 WSL /var/log/auth.log 수집 연결, PostgreSQL 이관, rsyslog 설정
- [ ] Sprint 3 — LLM 요약 계층 (일일 리포트 자연어 요약, 이상 패턴 해설), 설계 문서화
