"""도구 원본 출력 파서.

손으로 돌린 검증 도구의 출력 파일을 읽어 Ballista evidence 레코드로 변환한다.
익스플로잇 실행과 무관 — 이미 나온 결과를 읽어 기록·매핑만 한다.

각 파서는 (records, raw_bytes)를 반환:
  records : evidence로 append할 dict 리스트 (attack 매핑·결과·대상 포함)
  raw_bytes : 원본 출력(해시 보존용)

지원: nmap XML, nuclei JSONL. 새 도구는 parser 함수를 추가하고 PARSERS에 등록.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from xml.etree import ElementTree as ET


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_nmap_xml(raw: bytes) -> list[dict]:
    """nmap -oX 출력 → 호스트/서비스 발견 레코드.
    ATT&CK: T1046(서비스 탐지), T1018(호스트 탐지)."""
    root = ET.fromstring(raw)
    records = []
    # 스캔 시작 시각(있으면)
    start = root.get("start")
    ts = (datetime.fromtimestamp(int(start), tz=timezone.utc).isoformat()
          if start and start.isdigit() else _now())
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        open_ports = []
        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            if state_el is not None and state_el.get("state") == "open":
                svc_el = port.find("service")
                open_ports.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": svc_el.get("name") if svc_el is not None else None,
                    "product": svc_el.get("product") if svc_el is not None else None,
                    "version": svc_el.get("version") if svc_el is not None else None,
                })
        records.append({
            "tool_name": "nmap",
            "target": addr,
            "result": "success",
            "action_class": "read",
            "attack": {"tactic": "TA0007", "technique": "T1046",
                       "sub_technique": None, "attack_version": "15"},
            "finished_at": ts,
            "parsed": {"open_ports": open_ports},
        })
    return records


def parse_nuclei_jsonl(raw: bytes) -> list[dict]:
    """nuclei -jsonl 출력 → 취약점 탐지 findings 레코드(호스트 단위 집계).
    ATT&CK: T1595.002(능동 스캐닝-취약점 스캔)."""
    by_host: dict[str, list] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = rec.get("info", {})
        host = rec.get("host") or rec.get("matched-at") or "unknown"
        by_host.setdefault(host, []).append({
            "template_id": rec.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "host": host,
            "matched_at": rec.get("matched-at"),
            "classification": info.get("classification"),
        })
    records = []
    for host, findings in by_host.items():
        records.append({
            "tool_name": "nuclei",
            "target": host,
            "result": "success",
            "action_class": "read",
            "attack": {"tactic": "TA0043", "technique": "T1595",
                       "sub_technique": "T1595.002", "attack_version": "15"},
            "finished_at": _now(),
            "parsed": {"findings": findings},
        })
    return records


# 도구 이름 → 파서
PARSERS = {
    "nmap": parse_nmap_xml,
    "nuclei": parse_nuclei_jsonl,
}
