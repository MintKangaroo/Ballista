"""어시스턴트 프롬프트 빌더 — 역할 제약 포함 확인."""
from ballista.assistant.assistant import (SYSTEM_ROLE, build_summary_prompt,
                                          build_gap_prompt, build_learn_prompt)

def test_role_constrains_offense():
    # 역할에 공격 조언 거부가 명시돼 있어야 함
    assert "익스플로잇 방법" in SYSTEM_ROLE and "제시하지 않는다" in SYSTEM_ROLE

def test_prompts_include_role_and_context():
    dd={"KPI":[{"lab":"X","val":1}],"KILLCHAIN":[],"GAPS":[{"id":"T1021.002"}],"VULNS":[]}
    p=build_summary_prompt(dd)
    assert SYSTEM_ROLE in p and "T1021.002" in p
    g=build_gap_prompt([{"id":"T1190","txt":"..."}])
    assert SYSTEM_ROLE in g and "T1190" in g
    l=build_learn_prompt("T1046은 어떻게 탐지하나?")
    assert SYSTEM_ROLE in l and "T1046" in l
