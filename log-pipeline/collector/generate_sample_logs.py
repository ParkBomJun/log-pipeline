#!/usr/bin/env python3
"""테스트용 샘플 로그 생성기.

실제 운영에서는 /var/log/auth.log 와 방화벽 로그를 직접 수집하지만,
개발/테스트 단계에서는 재현 가능한 샘플 데이터가 필요하다.
auth.log(RFC3164 스타일)와 iptables 방화벽 로그 두 종류를 생성한다.

사용법:
    python3 generate_sample_logs.py            # 기본 500줄씩 생성
    python3 generate_sample_logs.py --lines 2000
"""
import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

HOSTS = ["web-01", "web-02", "db-01", "bastion"]
USERS = ["park", "admin", "deploy", "root", "guest", "oracle"]
ATTACKER_IPS = ["203.0.113.45", "198.51.100.7", "192.0.2.99"]
NORMAL_IPS = ["10.0.1.15", "10.0.1.22", "10.0.2.8"]
PORTS = [22, 80, 443, 3306, 8080, 5432]


def rand_time(base: datetime, spread_hours: int = 48) -> datetime:
    return base - timedelta(seconds=random.randint(0, spread_hours * 3600))


def gen_auth_line(ts: datetime) -> str:
    """auth.log 스타일 한 줄 생성. 실패 로그인을 의도적으로 다수 포함."""
    host = random.choice(HOSTS)
    pid = random.randint(1000, 99999)
    stamp = ts.strftime("%b %e %H:%M:%S")

    roll = random.random()
    if roll < 0.45:  # 로그인 실패 (브루트포스 시나리오)
        user = random.choice(USERS)
        ip = random.choice(ATTACKER_IPS + NORMAL_IPS[:1])
        return (f"{stamp} {host} sshd[{pid}]: Failed password for "
                f"{'invalid user ' if random.random() < 0.3 else ''}{user} "
                f"from {ip} port {random.randint(30000, 65000)} ssh2")
    elif roll < 0.75:  # 로그인 성공
        user = random.choice(USERS[:3])
        ip = random.choice(NORMAL_IPS)
        return (f"{stamp} {host} sshd[{pid}]: Accepted password for {user} "
                f"from {ip} port {random.randint(30000, 65000)} ssh2")
    elif roll < 0.9:  # 세션 종료
        user = random.choice(USERS[:3])
        return f"{stamp} {host} sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}"
    else:  # sudo 사용
        user = random.choice(USERS[:2])
        return (f"{stamp} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; "
                f"USER=root ; COMMAND=/usr/bin/systemctl restart nginx")


def gen_firewall_line(ts: datetime) -> str:
    """iptables 로그 스타일 한 줄 생성 (커널 로그 prefix 'FW-DROP:')."""
    host = random.choice(HOSTS)
    stamp = ts.strftime("%b %e %H:%M:%S")
    src = random.choice(ATTACKER_IPS if random.random() < 0.6 else NORMAL_IPS)
    dst = f"10.0.{random.randint(1, 3)}.{random.randint(1, 254)}"
    proto = random.choice(["TCP", "UDP"])
    return (f"{stamp} {host} kernel: FW-DROP: IN=eth0 OUT= "
            f"SRC={src} DST={dst} PROTO={proto} "
            f"SPT={random.randint(1024, 65000)} DPT={random.choice(PORTS)}")


def gen_attack_scenario(base: datetime) -> list[str]:
    """확정적 공격 시나리오 주입.

    무작위 로그만으로는 Q2b(시간 창)·Q3(실패 후 성공)가 우연에 의존한다.
    탐지 쿼리가 반드시 잡아낼 수 있도록, 명확한 브루트포스→침해 흐름을
    직접 구성해 반환한다. (SIEM 테스트에서 'known bad' 데이터를 심는 관행)
    """
    lines = []
    attacker = "203.0.113.45"
    target_host = "bastion"
    # 공격 시작 시점: 기준시각에서 대략 하루 전의 특정 5분 구간
    start = base - timedelta(days=1, hours=3)

    # 1) 5분 안에 admin 계정으로 20회 연속 실패 (시간 창 탐지에 확실히 걸림)
    for i in range(20):
        ts = start + timedelta(seconds=i * 12)  # 12초 간격 → 4분 안에 20회
        stamp = ts.strftime("%b %e %H:%M:%S")
        pid = 40000 + i
        lines.append(
            f"{stamp} {target_host} sshd[{pid}]: Failed password for admin "
            f"from {attacker} port {50000 + i} ssh2")

    # 2) 곧이어 같은 IP가 admin으로 로그인 성공 (계정 탈취 = Q3가 잡아야 할 것)
    ts = start + timedelta(minutes=5)
    stamp = ts.strftime("%b %e %H:%M:%S")
    lines.append(
        f"{stamp} {target_host} sshd[40099]: Accepted password for admin "
        f"from {attacker} port 50099 ssh2")

    # 3) 성공 직후 sudo로 권한 상승 시도 (침해 후 행위)
    ts = start + timedelta(minutes=5, seconds=30)
    stamp = ts.strftime("%b %e %H:%M:%S")
    lines.append(
        f"{stamp} {target_host} sudo: admin : TTY=pts/0 ; PWD=/home/admin ; "
        f"USER=root ; COMMAND=/bin/bash")
    return lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", type=int, default=500, help="파일당 생성 줄 수")
    ap.add_argument("--outdir", default="../sample_logs", help="출력 디렉토리")
    args = ap.parse_args()

    outdir = Path(__file__).parent / args.outdir
    outdir.mkdir(parents=True, exist_ok=True)
    base = datetime.now()

    auth_lines = sorted(
        (rand_time(base) for _ in range(args.lines)))
    with open(outdir / "auth.log", "w", encoding="utf-8") as f:
        # 무작위 배경 로그
        rendered = [gen_auth_line(ts) for ts in auth_lines]
        # 확정적 공격 시나리오 주입 후 시각순 정렬
        rendered += gen_attack_scenario(base)
        rendered.sort(key=lambda ln: (ln[:15]))  # syslog 타임스탬프 문자열 기준
        for line in rendered:
            f.write(line + "\n")

    fw_lines = sorted(
        (rand_time(base) for _ in range(args.lines)))
    with open(outdir / "firewall.log", "w", encoding="utf-8") as f:
        for ts in fw_lines:
            f.write(gen_firewall_line(ts) + "\n")

    print(f"생성 완료: {outdir}/auth.log, {outdir}/firewall.log ({args.lines}줄씩)")


if __name__ == "__main__":
    main()
