"""Action — Planner가 제안하거나 운용자가 정의하는 실행 요청 단위.

LLM Planner는 이 구조만 반환한다(직접 실행 권한 없음). 실행은 어댑터가 한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..attack.refs import AttackRef


@dataclass
class Action:
    action_id: str
    attack: AttackRef
    tool_name: str
    target: str
    params: dict = field(default_factory=dict)
    action_class: str = "read"          # "read" | "modify" | "destructive"
    rationale: str = ""                 # 이 기법을 고른 이유(감사용)
