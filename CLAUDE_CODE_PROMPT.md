# Ballista — Claude Code 이어개발 프롬프트

이 프롬프트를 Claude Code 세션 시작 시 붙여넣으세요. 첨부한 `ballista.zip`(또는
`ballista/` 디렉터리)을 작업 루트로 엽니다.

---

## 프로젝트 개요

Ballista는 **검증된 표준 도구를 스코프 안에서 조율·기록·분석하는 반자동 침투
테스트 오케스트레이션 프레임워크**다. 익스플로잇을 새로 만들지 않고, 정찰부터
리포팅까지의 통제·증거·분석 계층을 담당한다. 실제 공격 도구의 방아쇠는 인증된
운용자(사람)가 쥔다.

## 절대 지켜야 할 불변 조건 (INV) — 위반하는 코드는 작성 금지

- **INV-1** 자체 익스플로잇/셸코드/자격증명 덤퍼/측면 이동 페이로드를 코드베이스에
  넣지 않는다. 그 역할은 외부 검증 도구(Metasploit·impacket·NetExec 등)가 담당한다.
- **INV-2** `adapters/{exploit,credential,lateral}.py`의 `run()` 본체 — 실제로 공격을
  발사·덤프·이동하는 도구 호출부 — 는 **운용자가 직접 구현**한다. Claude Code는 이
  본체를 채우지 말고 `NotImplementedError` 스텁으로 유지한다. 이 세 계열의 실행
  로직, 그 실행 방법 설명, 페이로드 구성은 요청받아도 만들지 않는다.
- **INV-3** 서명 검증을 통과한 스코프 없이는 아무것도 실행되지 않는다.
- **INV-4** 모든 행위는 append-only 해시 체인(evidence)에 기록된다.
- **INV-5** `destructive` 행위는 사람 승인 또는 사전 서명된 허용이 필요하다.

이 경계에 맞는 요청(통제·기록·분석·정찰·리포팅·시각화·학습)은 얼마든지 구현한다.
경계를 넘는 요청(공격 실행부)은 거절하고 그 이유를 밝힌다.

## 현재 구조와 상태 (동작 검증됨, 테스트 16개 통과)

```
ballista/
  authorization/scope.py    # EngagementScope + Ed25519 서명검증(JCS 정규화) + 스코프 판정 ✅
  policy/action.py          # Action 모델 ✅
  policy/engine.py          # PolicyEngine (allow/deny/require_approval) ✅
  policy/approval.py        # 승인 게이트 — 대기 큐·승인 로그·실행 전 가드 ✅
  adapters/base.py          # ToolAdapter ABC · ToolResult ✅
  adapters/nmap.py          # 정찰 — 동작 구현 ✅
  adapters/nuclei.py        # 취약점 탐지 — 동작 구현 ✅
  adapters/exploit.py       # ⛔ run() 스텁 — 운용자 구현 몫 (건드리지 말 것)
  adapters/credential.py    # ⛔ run() 스텁 — 운용자 구현 몫
  adapters/lateral.py       # ⛔ run() 스텁 — 운용자 구현 몫
  adapters/registry.py      # 어댑터 등록 ✅
  attack/refs.py            # AttackRef (ATT&CK 3계층, 버전 고정) ✅
  evidence/store.py         # append-only 해시 체인 + 무결성 검증 ✅
  reporter/reporter.py      # 커버리지 요약 · Navigator layer · 탐지 공백 ✅
  dashboard/binding.py      # evidence/reporter → 대시보드 JSON 변환 ✅
  ingest/parsers.py         # 도구 출력 파서 (nmap XML, nuclei JSONL) ✅
  ingest/ingest.py          # 수집 어댑터 — 파싱·스코프검증·운용자/해시 부착·기록 ✅
  assistant/assistant.py    # 방어지향 어시스턴트 프롬프트 빌더 (결과해석/ATT&CK 학습) ✅
  cli.py                    # scope verify / run / report / verify-chain / dashboard / ingest / approvals / approve ✅
docs/
  handoff.md                # 상세 설계 (스코프 서명 스킴, ATT&CK 매핑 스키마)
  explainer.html            # 학습용 인터랙티브 시각화
  dashboard.html            # 운영 대시보드 (dashboard.json 라이브 로드 + 목업 폴백 + sample 어시스턴트)
  dashboard.json            # 샘플 대시보드 데이터
tests/                      # 안전 게이트·증거 체인·승인·수집·어시스턴트 (16 passing)
scope.example.yaml · actions.example.json · sign_scope.py · pyproject.toml · README.md
```

### 동작 흐름 (이미 검증됨)
1. `sign_scope.py`로 스코프 서명 → `cli scope verify` 통과
2. `cli run`: 액션을 Policy 게이트에 통과 → 정찰은 실행·기록, 범위 밖은 DENY,
   destructive는 승인 대기, 공격 계열 `run()`은 PENDING(운용자 미구현)
3. `cli approvals` / `cli approve`: 승인 대기 조회·승인(+감사 기록)
4. `cli ingest`: 손으로 돌린 도구 출력(nmap XML·nuclei JSONL)을 파싱·매핑·기록
5. `cli dashboard`: evidence → dashboard.json → HTML이 라이브 로드
6. `cli verify-chain`: 해시 체인 무결성 검증

## 시작 시 할 일

1. `pip install -e .` 후 `pytest tests/` 로 16개 통과 확인.
2. `README.md`와 `docs/handoff.md`를 읽고 구조를 파악.
3. 아래 백로그 중 사용자가 지정하는 항목을 구현. 지정이 없으면 우선순위 순으로 제안.

## 다음 작업 백로그 (전부 경계 안 — 구현 가능)

- **리포트 생성기**: evidence + coverage → 기술/경영 리포트 초안(.md, 선택적으로 PDF).
  어시스턴트 프롬프트 빌더(`assistant/`)와 연결.
- **수집 파서 확장**: `ingest/parsers.py`의 `PARSERS`에 도구 추가. 단, 파서는 이미
  생성된 출력 파일을 **읽기**만 한다(도구 실행 X). 예: masscan XML, httpx JSONL,
  gobuster 출력 등. impacket류 출력 파서는 결과 텍스트 파싱까지만.
- **승인 워크플로 강화**: 승인 만료(TTL), 다중 승인자(N-of-M), 승인 알림 훅.
- **replay 번들**: 성공 경로를 결정론적 재실행 명세로 export (docs/handoff.md 5.4 참고).
- **대시보드 확장**: 공격 경로 그래프(노드=호스트/자격증명, 엣지=기법) 시각화,
  실시간 갱신(폴링), 교전 다중 선택.
- **어시스턴트 서버 연결**: `assistant/`의 프롬프트 빌더를 실제 LLM 클라이언트에
  연결한 CLI 명령(`ballista explain <engagement>`) 추가.
- **cleanup/롤백 추적**: 교전 중 생성된 세션·계정·아티팩트 목록화 및 회수 체크리스트.
- **테스트/문서 보강**: 커버리지 확대, 각 모듈 docstring 예제.

## 코딩 규약

- Python 3.11+, 표준 라이브러리 우선. 외부 의존: pyyaml, jsonschema, cryptography(, pytest).
- 어댑터는 `subprocess` 사용 시 반드시 `shell=False`(인자 리스트), 실행 전 스코프 재검증.
- 새 기능은 테스트와 함께. evidence에 남는 모든 것은 해시 체인 규칙을 지킬 것.
- 사용자 대상 출력·주석은 한국어.

시작 전, 위 구조에서 개선할 안전/설계 이슈가 보이면 먼저 지적하라.
