"""Recon/vuln-detection adapter: nuclei 템플릿 스캐닝.

INV-1 준수: 취약점 '존재 여부 탐지'만 한다. 익스플로잇 실행이 아니다.
위험 태그(intrusive, dos, fuzzing)는 param_schema와 argv 양쪽에서 차단한다.
action_class = "read".

프로젝트 배치: ballista/adapters/nuclei.py
의존: ballista/adapters/base.py 의 ToolAdapter, ToolResult
      ballista/attack/refs.py 의 AttackRef
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from .base import ToolAdapter, ToolResult
from ..attack.refs import AttackRef


# 탐지 목적에서 벗어나는(파괴적/침습적) 태그는 항상 제외한다.
_ALWAYS_EXCLUDED_TAGS = ["dos", "intrusive", "fuzzing"]

# 허용 심각도 값
_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    action_class = "read"
    attack_techniques = [
        AttackRef("TA0043", "T1595", "T1595.002"),  # Active Scanning: Vuln Scanning
    ]

    param_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["targets"],
        "properties": {
            "targets": {
                "type": "array",
                "minItems": 1,
                "maxItems": 512,
                "items": {"type": "string"},
            },
            "severity": {
                "type": "array",
                "items": {"enum": sorted(_ALLOWED_SEVERITIES)},
                "default": ["medium", "high", "critical"],
            },
            # 포함할 태그(예: "cve", "misconfig"). 위험 태그는 어차피 강제 제외됨.
            "include_tags": {
                "type": "array",
                "items": {"type": "string", "pattern": r"^[a-z0-9\-]+$"},
            },
            "rate_limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 150},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 30, "default": 10},
        },
    }

    def __init__(self, scope, binary: str = "nuclei"):
        self._scope = scope
        self._binary = binary

    def _assert_targets_in_scope(self, targets: list[str]) -> None:
        for t in targets:
            host = self._host_of(t)
            if not self._scope.is_target_in_scope(host):
                raise PermissionError(f"target out of scope: {t}")

    @staticmethod
    def _host_of(target: str) -> str:
        # "https://app01.internal:8443/path" -> "app01.internal"
        t = target.split("://", 1)[-1]
        t = t.split("/", 1)[0]
        t = t.split(":", 1)[0]
        return t

    def _build_argv(self, p: dict) -> list[str]:
        argv = [
            self._binary,
            "-jsonl",                 # JSON lines 출력
            "-silent",
            "-rate-limit", str(p.get("rate_limit", 150)),
            "-timeout", str(p.get("timeout", 10)),
        ]
        for sev in p.get("severity", ["medium", "high", "critical"]):
            argv += ["-severity", sev]
        for tag in p.get("include_tags", []):
            argv += ["-tags", tag]
        # 위험 태그 강제 제외 — 스키마를 우회해도 여기서 막힌다.
        for tag in _ALWAYS_EXCLUDED_TAGS:
            argv += ["-exclude-tags", tag]
        for tgt in p["targets"]:
            argv += ["-target", tgt]
        return argv

    async def run(self, validated_params: dict) -> ToolResult:
        p = validated_params
        self._assert_targets_in_scope(p["targets"])
        argv = self._build_argv(p)

        started = datetime.now(timezone.utc)
        proc = await asyncio.create_subprocess_exec(
            *argv,                                     # shell=False
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        finished = datetime.now(timezone.utc)

        findings = self._parse_jsonl(out) if out else []

        return ToolResult(
            tool=self.name,
            argv=argv,
            returncode=proc.returncode,
            raw_output=out,
            stderr=err.decode(errors="replace"),
            parsed={"findings": findings},
            started_at=started,
            finished_at=finished,
            attack=self.attack_techniques[0],
        )

    @staticmethod
    def _parse_jsonl(out: bytes) -> list[dict]:
        findings = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = rec.get("info", {})
            findings.append({
                "template_id": rec.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "host": rec.get("host"),
                "matched_at": rec.get("matched-at"),
                # info.classification 안의 cve-id 등은 CTI Graph 연동에 유용
                "classification": info.get("classification"),
            })
        return findings
