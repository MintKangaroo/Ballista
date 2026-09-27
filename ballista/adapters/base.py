"""어댑터 공통 계약.

모든 어댑터(정찰이든 공격이든)는 이 껍데기를 공유한다:
- param_schema 로 허용 파라미터만 통과 (JSON Schema)
- run() 은 검증된 파라미터만 받고, subprocess는 shell=False
- 실행 전 스코프 재검증 (다중 방어)

INV-1: 어댑터는 자체 익스플로잇을 담지 않는다. 검증된 외부 도구 호출/파싱만 한다.
공격 실행 계열(exploit/credential/lateral)의 run() 본체는 운용자가 채운다.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

try:
    import jsonschema
except ImportError:      # 검증 라이브러리 없을 때도 임포트는 되도록
    jsonschema = None

from ..attack.refs import AttackRef


@dataclass
class ToolResult:
    tool: str
    argv: list[str]
    returncode: int
    raw_output: bytes
    stderr: str
    parsed: dict | None
    started_at: datetime
    finished_at: datetime
    attack: AttackRef


class ToolAdapter(ABC):
    name: str
    action_class: str                    # "read" | "modify" | "destructive"
    attack_techniques: list[AttackRef]
    param_schema: dict

    def validate(self, params: dict) -> dict:
        """param_schema로 검증. 실패 시 예외."""
        if jsonschema is not None:
            jsonschema.validate(params, self.param_schema)
        return params

    def _assert_targets_in_scope(self, targets) -> None:
        """스코프를 가진 어댑터는 이 훅으로 run 직전 재검증한다.
        (nmap/nuclei 어댑터가 자체 구현을 갖고 있음)"""
        scope = getattr(self, "_scope", None)
        if scope is None:
            return
        items = targets if isinstance(targets, (list, tuple)) else [targets]
        for t in items:
            if not scope.is_target_in_scope(t):
                raise PermissionError(f"target out of scope: {t}")

    @abstractmethod
    async def run(self, validated_params: dict) -> ToolResult:
        """검증된 외부 도구를 호출하고 ToolResult를 반환.
        공격 실행 계열은 여기서 NotImplementedError로 두고 운용자가 구현한다."""
        raise NotImplementedError
