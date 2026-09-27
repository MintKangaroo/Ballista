"""방어지향 어시스턴트 — 프롬프트 빌더.

역할(운용자 결정): 결과 해석·요약 + ATT&CK 학습 Q&A.
공격의 다음 단계나 익스플로잇 방법은 다루지 않는다 — 사후 해석·방어·학습 전용.

이 모듈은 '무엇을 물을지'(시스템 역할 + 컨텍스트가 붙은 프롬프트)를 구성한다.
실제 LLM 호출은 환경에 맞게 연결한다:
  - published 대시보드: sample capability (docs/dashboard.html에 구현됨)
  - CLI/서버: 원하는 LLM 클라이언트로 build_*_prompt() 결과를 전송

reporter.coverage_summary() / dashboard.binding.build_dashboard_data() 출력을
컨텍스트로 넘기면 된다.
"""

from __future__ import annotations

import json

SYSTEM_ROLE = (
    "너는 Ballista의 방어 분석 어시스턴트다. 이미 수집된 침투 테스트 결과(evidence)를 "
    "해석·요약하고, ATT&CK 기법을 방어자(SOC) 관점에서 설명한다. 규칙: 공격의 다음 단계, "
    "익스플로잇 방법, 페이로드, 특정 대상을 어떻게 공격·침투하는지는 절대 제시하지 않는다. "
    "그런 요청이 오면 정중히 거절하고 방어·탐지 관점으로 돌린다. 답변은 한국어로 간결하게."
)


def build_summary_prompt(dashboard_data: dict) -> str:
    """대시보드 데이터(build_dashboard_data 출력) → 교전 요약 프롬프트."""
    ctx = {
        "KPI": dashboard_data.get("KPI"),
        "KILLCHAIN": dashboard_data.get("KILLCHAIN"),
        "GAPS": dashboard_data.get("GAPS"),
        "VULNS": dashboard_data.get("VULNS"),
    }
    return (SYSTEM_ROLE + "\n\n다음은 이번 교전의 요약 데이터다:\n"
            + json.dumps(ctx, ensure_ascii=False)
            + "\n\n무슨 일이 있었고 방어 관점에서 무엇이 중요한지 6~8줄로 요약해줘.")


def build_gap_prompt(gaps: list[dict]) -> str:
    """탐지 공백 목록 → 항목별 방어 권고 프롬프트."""
    return (SYSTEM_ROLE + "\n\n다음은 탐지 공백(성공했으나 미탐지) 목록이다:\n"
            + json.dumps(gaps, ensure_ascii=False)
            + "\n\n각 항목을 어떤 로그·탐지 룰·완화책으로 메우면 좋을지 항목별 방어 권고로 제시해줘.")


def build_learn_prompt(question: str) -> str:
    """ATT&CK/방어 학습 질문 프롬프트."""
    return SYSTEM_ROLE + "\n\n사용자 질문(ATT&CK·방어 학습): " + question
