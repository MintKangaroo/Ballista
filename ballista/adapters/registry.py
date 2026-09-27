"""어댑터 레지스트리.

스코프에 묶어 어댑터 인스턴스를 만들고 이름으로 조회한다.
Planner가 제안한 tool_name이 여기 없으면 폐기된다(등록된 것만 실행 가능).
"""

from __future__ import annotations

from .base import ToolAdapter
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .exploit import ExploitAdapter
from .credential import CredentialAdapter
from .lateral import LateralAdapter


def build_registry(scope) -> dict[str, ToolAdapter]:
    adapters = [
        NmapAdapter(scope),
        NucleiAdapter(scope),
        ExploitAdapter(scope),        # run() 미구현 — 호출 시 NotImplementedError
        CredentialAdapter(scope),
        LateralAdapter(scope),
    ]
    return {a.name: a for a in adapters}
