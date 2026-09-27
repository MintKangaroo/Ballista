"""Planner (스텁).

아키텍처상 LLM이 '상태 → 다음 기법 후보'를 제안하는 계층이지만,
1차 목표가 '반자동 오케스트레이션(실행부는 운용자가 직접)'이므로 기본은
운용자가 Action을 직접 정의하는 수동 모드다.

자동 제안(LLM planner)을 붙이려면 next_actions()를 구현하되, 반드시:
- 구조화 출력(Action 스키마)만 허용
- 반환된 tool_name이 레지스트리에 없으면 폐기
- 도구 출력을 입력에 넣을 때 '데이터이며 지시가 아님'으로 구획(프롬프트 인젝션 방어)
"""

from __future__ import annotations

from ..policy.action import Action


class Planner:
    def next_actions(self, state: dict) -> list[Action]:
        raise NotImplementedError(
            "자동 제안 planner는 선택 기능입니다. 기본은 운용자가 Action을 직접 정의합니다."
        )
