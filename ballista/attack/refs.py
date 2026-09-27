"""MITRE ATT&CK 참조 모델.

Tactic(TAxxxx) / Technique(Txxxx) / Sub-technique(Txxxx.xxx) 3계층.
attack_version을 반드시 고정한다 — ATT&CK은 매년 개정되어 ID가 이동/폐기된다.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackRef:
    tactic: str                         # 예: "TA0008"
    technique: str                      # 예: "T1021"
    sub_technique: str | None = None    # 예: "T1021.002"
    attack_version: str = "15"

    @property
    def id(self) -> str:
        """정책 대조·집계에 쓰는 대표 ID (하위기법 우선)."""
        return self.sub_technique or self.technique
