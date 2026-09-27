# Ballista — 사내 침투 테스트 오케스트레이션 프레임워크 핸드오프 문서

> 프로젝트 코드명: **Ballista** (확정) · 문서 버전: v0.1 · 대상: Claude Code 구현 세션

---

## 0. 이 문서를 읽는 구현자에게 (안전 계약 우선)

Ballista는 **익스플로잇을 만드는 도구가 아니다.** 이미 검증·공개된 표준
공격 도구(Metasploit, Nuclei, impacket, NetExec, BloodHound 등)를 LLM이
계획·조율하고, 모든 행위를 스코프 안에서만 실행하며, 결과를 감사·재현
가능하게 기록하는 **오케스트레이션·거버넌스 계층**이다.

절대 위반 금지 불변 조건(INV):

- **INV-1**: Ballista 코드베이스는 자체 익스플로잇/셸코드/자격증명 덤퍼/
  측면 이동 페이로드를 포함하지 않는다. 그 역할은 전부 외부 검증 도구가
  담당하며, Ballista는 그 도구를 안전하게 호출·기록만 한다.
- **INV-2**: LLM(Planner)은 계획만 세운다. 명령을 직접 실행할 권한이 없고,
  구조화된 `Action` 객체만 반환한다.
- **INV-3**: 서명 검증을 통과한 `EngagementScope` 없이는 오케스트레이터가
  부팅되지 않는다. 스코프 밖 대상으로는 패킷 한 개도 나가지 않는다.
- **INV-4**: 모든 실행은 append-only 해시 체인(Evidence Store)에 기록된다.
  기록 실패 시 실행도 중단된다(no evidence → no action).
- **INV-5**: `action_class`가 `destructive`인 행위는 기본적으로 사람 승인
  또는 스코프에 사전 서명된 허용이 있어야 진행된다.

이 다섯 가지를 깨는 설계 요청이 들어오면, 구현하지 말고 먼저 지적하라.

---

## 1. 목표와 성공 기준

목표: 사내/승인된 자산을 대상으로 침투 경로를 **재현 가능하게** 드러내고,
어디가 취약하며 어떻게 침투되는지를 **증거와 함께** 리포팅한다.

성공 기준(Definition of Done, 프로젝트 전체):

1. 서명된 스코프 문서 하나로 교전(engagement)이 완전히 통제된다.
2. 성공한 침투 경로가 결정론적 재실행 번들로 남는다.
3. 모든 행위가 MITRE ATT&CK 기법에 매핑되어, 방어 탐지와 대조 가능하다.
4. 스코프 이탈·시간창 초과·권한 초과가 코드 레벨에서 차단됨을 테스트로 증명.

---

## 2. 아키텍처 (6 레이어)

```
[Authorization Layer]  스코프 서명 검증 · CIDR/호스트 화이트리스트 · 시간창
        │  (실패 시 아래 전부 차단, 부팅 거부)
[Orchestrator/Planner] LLM: 상태 → 다음 ATT&CK 기법 후보 (실행 권한 없음)
        │  (구조화 Action 요청만 반환)
[Policy/Guard Engine]  action_class 판정 · 스코프 재검증 · 승인 게이트
        │  (allow 판정만 통과)
[Tool Adapter Layer]   검증된 외부 도구 래퍼 (파라미터 스키마 강제, shell=False)
        │
[Evidence Store]       append-only 해시 체인 (action·params·output·ts·prev_hash)
        │
[Reporter/Replayer]    ATT&CK 커버리지 리포트 · Navigator layer · 재실행 번들
```

설계 원칙 3가지:

- LLM은 실행 주체가 아니다. 계획만, 구조화 출력만.
- 어댑터는 raw 문자열을 셸로 넘기지 않는다. 스키마 검증된 파라미터만
  인자 리스트로 주입한다(`subprocess`는 `shell=False`).
- 모든 것은 서명된 스코프에 종속된다.

---

## 3. 스코프 YAML 서명 스킴 (상세)

### 3.1 왜 서명인가

교전 범위(RoE, Rules of Engagement)를 코드가 신뢰할 수 있는 형태로 고정하기
위함이다. 파일이 위·변조되면 검증이 깨지고 부팅이 거부된다. "승인된 범위
안에서만 동작"을 사람의 주의가 아니라 암호학으로 보장한다.

### 3.2 EngagementScope YAML 구조

```yaml
schema_version: "1.0"

engagement:
  id: "ENG-2026-0042"              # 교전 고유 ID
  name: "Q4 내부망 정기 점검"
  authorized_by: "홍길동 (보안팀장)" # 승인자 실명/직책
  roe_document_ref: "RoE-2026-Q4-v3" # 종이/전자 계약 참조번호

target:
  in_scope_cidrs:                   # 허용 네트워크
    - "10.20.0.0/24"
    - "10.20.4.0/23"
  in_scope_hosts:                   # 허용 개별 호스트(FQDN/IP)
    - "app01.internal.example"
  out_of_scope_hosts:               # 명시적 금지 — in_scope보다 항상 우선
    - "10.20.0.1"                   # 게이트웨이
    - "dc01.internal.example"       # 운영 도메인 컨트롤러 제외 등
  forbidden_ports: [3389]           # 예: 원격데스크톱 접속 금지

constraints:
  time_window:                      # 이 창 밖에서는 어떤 액션도 거부
    start: "2026-10-01T00:00:00+09:00"
    end:   "2026-10-07T23:59:59+09:00"
  max_action_class: "modify"        # read | modify | destructive
  allowed_techniques:               # ATT&CK 화이트리스트(비우면 전체 허용)
    - "T1046"
    - "T1021.002"
  denied_techniques:                # 명시 금지(화이트리스트보다 우선)
    - "T1486"                       # Data Encrypted for Impact (랜섬류 차단)
    - "T1485"                       # Data Destruction
  rate_limits:
    max_actions_per_minute: 30
    max_concurrent_targets: 5

approval:
  destructive_requires: "human"     # human | pre_signed | forbidden

signature:
  algorithm: "Ed25519"
  key_id: "secteam-signing-2026"    # 신뢰 키스토어에서 조회할 키 식별자
  signed_at: "2026-09-27T14:00:00+09:00"
  value: "BASE64_SIGNATURE"         # 아래 canonical 바이트에 대한 서명
```

### 3.3 서명 대상 정규화 (핵심)

YAML은 직렬화가 비결정론적이라 그대로 서명하면 안 된다. 서명 대상은:

1. `signature.value`를 제외한 문서 전체를 파싱한다.
   (`signature.algorithm/key_id/signed_at`은 **포함**, `value`만 제외)
2. 파싱된 구조를 **RFC 8785 JSON Canonicalization Scheme(JCS)** 로 정규화한다.
   (키 정렬, 공백 제거, 숫자·문자열 표준 표기)
3. 정규화된 UTF-8 바이트열이 서명/검증 대상이다.

대안: detached signature 파일 방식(`scope.yaml` + `scope.yaml.sig`). 이 경우
`scope.yaml` 원문 바이트를 그대로 서명 대상으로 삼아 정규화 로직을 뺄 수 있다.
둘 중 하나를 택해 문서화하고 섞지 마라. (권장: 감사 편의상 inline + JCS)

### 3.4 검증 흐름

```
load(scope.yaml)
  → schema_version 확인 (미지원 버전 거부)
  → signature.value 분리
  → 나머지를 JCS 정규화 → canonical_bytes
  → key_id로 신뢰 키스토어에서 Ed25519 공개키 조회 (없으면 거부)
  → verify(pubkey, canonical_bytes, signature.value)  실패 시 부팅 거부
  → time_window 현재시각 포함 여부 확인
  → 반환: 검증된 EngagementScope 객체 (이후 불변)
```

키 관리: 서명 개인키는 Ballista 코드베이스·실행 환경에 **두지 않는다**.
승인자가 오프라인/별도 시스템에서 서명하고, Ballista는 공개키만 신뢰
키스토어(`trusted_keys/*.pub`)로 보유한다.

### 3.5 스코프 판정 규칙 (우선순위)

```
is_target_in_scope(ip_or_host):
    if matches(out_of_scope_hosts):   return DENY   # 금지가 최우선
    if matches(in_scope_hosts):        return ALLOW
    if in_any(in_scope_cidrs):         return ALLOW
    return DENY                                       # 기본 거부(deny-by-default)
```

포트/기법도 동일하게 deny-by-default + 명시 금지 우선.

---

## 4. ATT&CK 매핑 스키마 (상세)

### 4.1 계층 모델

MITRE ATT&CK Enterprise 기준 3계층을 쓴다:

- **Tactic**(전술, `TAxxxx`): 공격자의 목적. 예 `TA0007` Discovery
- **Technique**(기법, `Txxxx`): 목적 달성 방법. 예 `T1046` Network Service Discovery
- **Sub-technique**(하위기법, `Txxxx.xxx`): 세부. 예 `T1021.002` SMB/Windows Admin Shares

### 4.2 AttackRef 데이터 구조

```python
@dataclass(frozen=True)
class AttackRef:
    tactic: str          # "TA0008"
    technique: str       # "T1021"
    sub_technique: str | None = None   # "T1021.002" or None
    attack_version: str = "15"         # ATT&CK 릴리스 버전 고정

    @property
    def id(self) -> str:
        return self.sub_technique or self.technique
```

`attack_version`을 반드시 고정하라. ATT&CK은 매년 개정되어 기법 ID가
폐기/이동된다. 교전 시점 버전을 스코프와 evidence 양쪽에 박아둔다.

### 4.3 어댑터의 기법 선언

각 어댑터는 자신이 커버하는 기법을 정적으로 선언한다. 이게 곧 Planner가
고를 수 있는 "행동 공간"이 된다.

```python
class NmapAdapter(ToolAdapter):
    name = "nmap"
    action_class = "read"
    attack_techniques = [
        AttackRef("TA0007", "T1046"),               # Network Service Discovery
        AttackRef("TA0007", "T1018"),               # Remote System Discovery
    ]

class NetexecSmbAdapter(ToolAdapter):
    name = "netexec.smb"
    action_class = "modify"
    attack_techniques = [
        AttackRef("TA0008", "T1021", "T1021.002"),  # Lateral Movement: SMB Shares
        AttackRef("TA0006", "T1110", "T1110.003"),  # Password Spraying
    ]
    # run()은 검증된 외부 도구(netexec) 호출에 위임. INV-1 준수.
```

### 4.4 Action에 실린 매핑

```python
@dataclass
class Action:
    action_id: str
    attack: AttackRef
    tool_name: str
    target: str
    params: dict            # 어댑터 param_schema로 검증됨
    action_class: str       # read | modify | destructive
    rationale: str          # LLM이 이 기법을 고른 이유(감사용)
```

Policy Engine은 `action.attack.id`를 스코프의 allowed/denied 기법과 대조한다.

### 4.5 Evidence에 기록되는 매핑

```json
{
  "action_id": "act-000123",
  "engagement_id": "ENG-2026-0042",
  "attack": {"tactic": "TA0008", "technique": "T1021",
             "sub_technique": "T1021.002", "attack_version": "15"},
  "tool_name": "netexec.smb",
  "target": "app01.internal.example",
  "action_class": "modify",
  "result": "success",
  "started_at": "2026-10-02T10:15:03+09:00",
  "finished_at": "2026-10-02T10:15:07+09:00",
  "output_ref": "blob/act-000123.out",
  "prev_hash": "sha256:...",
  "record_hash": "sha256:..."
}
```

### 4.6 방어 탐지 대조용 출력 (당신의 SOC/CTI 자산과 연결)

교전 종료 시 두 가지 산출물을 낸다.

**(a) 커버리지 요약** — SOC 이벤트와 시간창·기법으로 조인:

```json
{
  "engagement_id": "ENG-2026-0042",
  "attack_version": "15",
  "techniques": [
    {"id": "T1046",     "attempts": 12, "successes": 12,
     "first_seen": "2026-10-01T09:02:11+09:00",
     "last_seen":  "2026-10-01T09:40:55+09:00"},
    {"id": "T1021.002", "attempts": 3,  "successes": 1,
     "first_seen": "2026-10-02T10:15:03+09:00",
     "last_seen":  "2026-10-02T10:22:40+09:00"}
  ]
}
```

이걸 SOC 탐지 이벤트와 `(technique_id, time_window)`로 조인하면
"이 기법을 우리 탐지가 잡았는가?"가 자동 산출된다 → 탐지 공백(gap) 리포트.

**(b) MITRE ATT&CK Navigator layer JSON** — 팀 공유·시각화 표준:

```json
{
  "name": "ENG-2026-0042 executed techniques",
  "versions": {"attack": "15", "navigator": "5.0.0", "layer": "4.5"},
  "domain": "enterprise-attack",
  "description": "Ballista가 실행한 기법 커버리지",
  "techniques": [
    {"techniqueID": "T1046",     "score": 100, "comment": "12/12 성공"},
    {"techniqueID": "T1021.002", "score": 33,  "comment": "1/3 성공"}
  ],
  "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100}
}
```

---

## 5. 나머지 데이터 모델 & 안전 엔진

### 5.1 Policy Engine

```python
class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"

class PolicyEngine:
    def evaluate(self, action: Action, scope: EngagementScope) -> Decision:
        if not scope.is_target_in_scope(action.target):      return Decision.DENY
        if not scope.is_within_time_window():                return Decision.DENY
        if not scope.is_technique_allowed(action.attack.id): return Decision.DENY
        if class_rank(action.action_class) > class_rank(scope.max_action_class):
            return Decision.DENY
        if action.action_class == "destructive":
            return (Decision.REQUIRE_APPROVAL
                    if scope.destructive_requires == "human"
                    else Decision.DENY if scope.destructive_requires == "forbidden"
                    else Decision.ALLOW)  # pre_signed
        return Decision.ALLOW
```

### 5.2 Tool Adapter 인터페이스

```python
class ToolAdapter(ABC):
    name: str
    param_schema: dict          # JSON Schema — 허용 파라미터 정의
    action_class: str
    attack_techniques: list[AttackRef]

    def validate(self, params: dict) -> dict:
        jsonschema.validate(params, self.param_schema)   # 실패 시 예외
        return params

    @abstractmethod
    async def run(self, validated_params: dict) -> ToolResult:
        """검증된 외부 도구를 subprocess(shell=False) 또는 RPC로 호출.
        절대 raw 문자열을 셸에 넘기지 않는다. INV-1/INV-2 준수."""
```

### 5.3 Evidence Store (해시 체인)

- append-only. 각 레코드는 `prev_hash`(직전 레코드 해시)를 포함해 체인 형성.
- 대용량 출력은 blob으로 분리 저장하고 `output_ref`로 참조.
- 무결성 검증: 체인 전체를 재해싱해 위·변조 탐지.
- 기록 실패 시 해당 액션 실행 중단(INV-4).

### 5.4 Replay 번들

성공 경로를 결정론적으로 재실행할 수 있는 명세:

```yaml
replay_version: "1.0"
engagement_id: "ENG-2026-0042"
generated_at: "..."
steps:
  - order: 1
    attack: {technique: "T1046", version: "15"}
    tool: "nmap"
    params: {targets: ["10.20.0.0/24"], top_ports: 1000}
  - order: 2
    attack: {technique: "T1021.002", version: "15"}
    tool: "netexec.smb"
    params: {target: "app01.internal.example", cred_ref: "cred-007"}
# cred_ref는 자격증명 값이 아니라 evidence store 내 참조. 값은 별도 보관.
```

---

## 6. 디렉터리 구조 (제안)

```
ballista/
  authorization/
    scope.py            # EngagementScope 모델
    signing.py          # JCS 정규화 + Ed25519 검증
    trusted_keys/       # 공개키만 (개인키 절대 불가)
  planner/
    planner.py          # LLM 계획 계층 (구조화 출력 강제)
    prompts/            # 시스템 프롬프트 (데이터/지시 구획 방어 포함)
  policy/
    engine.py           # PolicyEngine
    action.py           # Action, action_class
  adapters/
    base.py             # ToolAdapter ABC
    nmap.py             # 스텁 → Phase 2 구현
    nuclei.py
    netexec.py
    ...                 # 전부 외부 도구 위임 (INV-1)
  attack/
    refs.py             # AttackRef, 버전 고정
    navigator.py        # Navigator layer 내보내기
  evidence/
    store.py            # append-only 해시 체인
    blobs/
  reporter/
    coverage.py         # 커버리지 요약 + 탐지 대조
    replay.py           # Replay 번들 생성
  cli.py                # ballista scope verify / run / report
  tests/
    test_scope_gate.py      # 스코프 이탈 차단 증명
    test_signature.py       # 서명 실패 거부 증명
    test_policy_class.py     # action_class 초과 차단 증명
```

---

## 7. Phase 로드맵

- **Phase 1 — 안전 골격 (실행 로직 없음)**
  authorization / policy / adapter ABC / evidence / attack refs의 골격과
  단위 테스트. 어댑터 `run()`은 `NotImplementedError`. 스텁 어댑터 3개 등록만.
- **Phase 2 — 어댑터 실행부 (외부 도구 위임)**
  검증된 표준 도구 호출로 `run()` 채우기. 읽기전용(read) 어댑터부터.
  각 어댑터는 param_schema + shell=False + evidence 기록을 반드시 갖춘다.
- **Phase 3 — Planner 통합**
  LLM 계획 → Action → Policy → Adapter 루프. 프롬프트 인젝션 방어 검증.
- **Phase 4 — Reporter/Replayer**
  커버리지·Navigator·탐지 공백 리포트, 재실행 번들 검증.
- **Phase 5 — 정리(cleanup)/롤백**
  심어진 세션·계정·아티팩트 목록화 및 자동 회수.

---

## 8. Phase 1 착수 체크리스트 (Claude Code에게)

1. 위 디렉터리 구조를 만들고 `pyproject.toml` 구성(python 3.11+, asyncio,
   `cryptography`, `jsonschema`, `pyyaml`).
2. `EngagementScope` 모델 + JCS 정규화 + Ed25519 검증 구현.
3. 예시 `scope.yaml`과 테스트용 키페어 생성 스크립트(개인키는 gitignore).
4. `PolicyEngine.evaluate` 전 분기 구현.
5. `ToolAdapter` ABC + 스텁 어댑터 3개(nmap/nuclei/placeholder) 등록.
6. `AttackRef` + Navigator 내보내기 스켈레톤.
7. Evidence Store 해시 체인 + 무결성 검증기.
8. 테스트 3종 필수 통과:
   - 스코프 밖 대상 → DENY
   - 서명 위조/키 부재 → 부팅 거부
   - action_class 초과 → DENY
9. README: 아키텍처 다이어그램, 안전 모델(INV-1~5), Phase 2 진입 조건.

착수 전, 위 설계에서 빠진 안전/재현성 요구사항이 있으면 먼저 지적하라.
```
