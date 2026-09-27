"""Recon adapter: nmap 서비스/호스트 디스커버리.

INV-1 준수: 익스플로잇 로직 없음. 외부 nmap 바이너리 호출 + 결과 파싱만 한다.
action_class = "read" (능동 스캔이지만 대상 상태를 바꾸지 않음).

프로젝트 배치: ballista/adapters/nmap.py
의존: ballista/adapters/base.py 의 ToolAdapter, ToolResult
      ballista/attack/refs.py 의 AttackRef
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from .base import ToolAdapter, ToolResult
from ..attack.refs import AttackRef


# 허용 스캔 타입만 화이트리스트로 고정. 임의 nmap 플래그 주입을 원천 차단한다.
_ALLOWED_SCAN_TYPES = {
    "connect": "-sT",   # TCP connect — 권한 불필요, 가장 안전
    "syn": "-sS",       # SYN 스캔 — root 필요
    "ping": "-sn",      # 호스트 디스커버리만
}


class NmapAdapter(ToolAdapter):
    name = "nmap"
    action_class = "read"
    attack_techniques = [
        AttackRef("TA0007", "T1046"),   # Network Service Discovery
        AttackRef("TA0007", "T1018"),   # Remote System Discovery
    ]

    param_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["targets"],
        "properties": {
            "targets": {
                "type": "array",
                "minItems": 1,
                "maxItems": 256,
                "items": {"type": "string"},
            },
            "scan_type": {"enum": list(_ALLOWED_SCAN_TYPES), "default": "connect"},
            "top_ports": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 1000},
            # 명시 포트 지정 시에도 숫자/콤마/하이픈만 허용 (예: "22,80,443", "1-1024")
            "ports": {"type": "string", "pattern": r"^[0-9,\-]+$"},
            "timing": {"type": "integer", "minimum": 0, "maximum": 4, "default": 3},
        },
    }

    def __init__(self, scope, binary: str = "nmap"):
        self._scope = scope        # 검증된 EngagementScope — run 직전 재검증에 사용
        self._binary = binary

    def _assert_targets_in_scope(self, targets: list[str]) -> None:
        """Policy 통과 후에도 어댑터 레벨에서 한 번 더 확인(다중 방어)."""
        for t in targets:
            if not self._scope.is_target_in_scope(t):
                raise PermissionError(f"target out of scope: {t}")

    def _build_argv(self, p: dict) -> list[str]:
        # -oX - : XML을 stdout으로. 파싱 안정성을 위해 항상 XML 출력.
        argv = [self._binary, "-oX", "-", "-T", str(p.get("timing", 3))]
        argv.append(_ALLOWED_SCAN_TYPES[p.get("scan_type", "connect")])
        if "ports" in p:
            argv += ["-p", p["ports"]]
        else:
            argv += ["--top-ports", str(p.get("top_ports", 1000))]
        argv += p["targets"]       # 인자 리스트 방식 — 셸 해석/인젝션 없음
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

        parsed = None
        if proc.returncode == 0 and out:
            try:
                parsed = self._parse_xml(out)
            except ET.ParseError:
                parsed = None

        return ToolResult(
            tool=self.name,
            argv=argv,
            returncode=proc.returncode,
            raw_output=out,
            stderr=err.decode(errors="replace"),
            parsed=parsed,
            started_at=started,
            finished_at=finished,
            attack=self.attack_techniques[0],
        )

    @staticmethod
    def _parse_xml(xml_bytes: bytes) -> dict:
        root = ET.fromstring(xml_bytes)
        hosts = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else None
            ports = []
            for port in host.findall("./ports/port"):
                state_el = port.find("state")
                svc_el = port.find("service")
                ports.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "state": state_el.get("state") if state_el is not None else None,
                    "service": svc_el.get("name") if svc_el is not None else None,
                    "product": svc_el.get("product") if svc_el is not None else None,
                    "version": svc_el.get("version") if svc_el is not None else None,
                })
            hosts.append({"address": addr, "ports": ports})
        return {"hosts": hosts}
