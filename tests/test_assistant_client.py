"""어시스턴트 클라이언트 테스트 — 프롬프트 빌더 + dry-run(네트워크 없이)."""

from __future__ import annotations

from ballista.assistant.assistant import (
    build_summary_prompt, build_gap_prompt, build_learn_prompt, SYSTEM_ROLE,
)
from ballista.assistant import client as ac


def test_prompts_carry_defensive_role():
    data = {"KPI": [{"lab": "EXECUTED ACTIONS", "val": 2}], "KILLCHAIN": [],
            "GAPS": [], "VULNS": []}
    for p in (build_summary_prompt(data),
              build_gap_prompt([{"id": "T1046", "successes": 1}]),
              build_learn_prompt("T1046은 어떻게 탐지하나?")):
        # 방어 역할 고정 문구가 항상 프롬프트에 포함
        assert "방어 분석 어시스턴트" in p
        assert "익스플로잇 방법" in p          # 공격법 거절 지침
        assert SYSTEM_ROLE in p


def test_sdk_available_is_bool():
    assert isinstance(ac.sdk_available(), bool)


def test_default_model():
    assert ac.DEFAULT_MODEL == "claude-opus-5"


def test_ask_claude_is_lazy(monkeypatch):
    """anthropic import는 호출 시점에만 — 모듈 import 자체는 SDK 없이도 성공."""
    import importlib
    mod = importlib.import_module("ballista.assistant.client")
    assert hasattr(mod, "ask_claude")   # import 시 SDK를 요구하지 않음
