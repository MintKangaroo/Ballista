"""Credential 어댑터 (스텁).

INV-1: 자격증명 탈취 구현체를 프레임워크에 담지 않는다.
run() 본체 — 검증된 외부 도구(예: impacket)로 자격증명을 확보하는 호출부 —
는 인증된 운용자가 자신의 환경에서 구현한다.
결과를 ToolResult로 반환하면 evidence 체인에 기록되고 reporter가 집계한다.
"""

from __future__ import annotations

from .base import ToolAdapter, ToolResult
from ..attack.refs import AttackRef


class CredentialAdapter(ToolAdapter):
    name = "credential"
    action_class = "modify"
    attack_techniques = [
        AttackRef("TA0006", "T1003"),            # OS Credential Dumping
    ]
    param_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["target"],
        "properties": {
            "target": {"type": "string"},
        },
    }

    def __init__(self, scope):
        self._scope = scope

    async def run(self, validated_params: dict) -> ToolResult:
        self._assert_targets_in_scope(validated_params["target"])
        # ── 여기 실제 도구 호출부를 구현 ──
        raise NotImplementedError("credential run() 본체는 운용자가 구현합니다.")
