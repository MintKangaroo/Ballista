"""Lateral Movement 어댑터 (스텁).

INV-1: 측면 이동 실행 코드를 프레임워크에 담지 않는다.
run() 본체 — 검증된 외부 도구(예: NetExec/impacket psexec·wmiexec)로
다른 시스템으로 이동하는 호출부 — 는 인증된 운용자가 구현한다.

특히 측면 이동은 대상마다 스코프 재검증이 필수다(_assert_targets_in_scope).
"""

from __future__ import annotations

from .base import ToolAdapter, ToolResult
from ..attack.refs import AttackRef


class LateralAdapter(ToolAdapter):
    name = "lateral"
    action_class = "modify"
    attack_techniques = [
        AttackRef("TA0008", "T1021", "T1021.002"),   # Remote Services: SMB Admin Shares
    ]
    param_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["target"],
        "properties": {
            "target": {"type": "string"},
            # 참조 메타데이터(실행 값 아님): 출발 호스트·자격증명 참조
            "source": {"type": "string"},
            "cred_ref": {"type": "string"},
        },
    }

    supports_simulation = True

    def __init__(self, scope):
        self._scope = scope

    async def run(self, validated_params: dict) -> ToolResult:
        self._assert_targets_in_scope(validated_params["target"])   # 이동 대상 재검증
        # ── 여기 실제 도구 호출부를 구현 ──
        raise NotImplementedError("lateral run() 본체는 운용자가 구현합니다.")

    def simulate(self, validated_params: dict) -> ToolResult:
        """실행 없이 파이프라인 검증용 합성 결과. 실제 이동/접속 없음."""
        return self._simulated_result(validated_params["target"],
                                      "측면 이동 시뮬레이션(가상). 실제 접속·이동 없음.")
