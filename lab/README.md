# lab — 양성(benign) 표적 정찰 파이프라인 검증 하니스

Ballista가 실제로 담당하는 부분(정찰 → 스코프 게이팅 → 증거 체인 → 리포트)을
**라이브 대상에서** 검증하기 위한 데모다.

> 표적은 **취약점을 심지 않은 평범한 nginx**다. 침투/익스플로잇 데모가 아니라,
> 프레임워크의 통제·기록·분석 계층이 실제로 동작하는지 확인하는 용도다.

## 실행

```bash
# 1) 양성 표적 컨테이너 (평범한 nginx, 취약점 없음)
docker run -d --name ballista-lab \
  -p 127.0.0.1:18080:80 -p 127.0.0.1:18443:80 \
  -v "$PWD/lab/index.html":/usr/share/nginx/html/index.html:ro nginx:alpine

# 2) 테스트 스코프 서명 (예제 키와 분리된 전용 key_id/keydir)
python sign_scope.py lab/scope.lab.yaml lab/keys
python -m ballista.cli scope verify lab/scope.lab.yaml lab/keys

# 3) 라이브 정찰 실행 (범위 밖 8.8.8.8은 DENY 되어야 정상)
python -m ballista.cli run lab/scope.lab.yaml lab/keys lab/actions.lab.json --db lab/evidence.db

# 4) 무결성·리포트
python -m ballista.cli verify-chain ENG-LAB-0001 --db lab/evidence.db
python -m ballista.cli report-doc lab/scope.lab.yaml lab/keys --db lab/evidence.db \
    --out lab/report.md --with-prompts

# 정리
docker rm -f ballista-lab
```

## 검증 결과 (실측)

- nmap 라이브 스캔이 실제 열린 포트 탐지: `22/ssh`, `18080`, `18443`
- 범위 밖 `8.8.8.8` → `[DENY] target out of scope` (스코프 게이팅 동작)
- 증거 해시 체인: `체인 무결: OK`
- `report-doc` → evidence 기반 기술/경영 리포트 초안 생성

생성물(`lab/evidence.db`, `lab/keys/`, `lab/report.md`)은 `.gitignore` 대상이다.
