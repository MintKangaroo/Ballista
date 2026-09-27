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
import re
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


def parse_masscan_xml(raw: bytes) -> list[dict]:
    """masscan -oX 출력 → 호스트/열린 포트 레코드.
    masscan XML은 nmap과 유사한 구조(host/address/ports/port/state)를 쓴다.
    ATT&CK: T1046(네트워크 서비스 탐지)."""
    root = ET.fromstring(raw)
    records = []
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
                })
        if not open_ports:
            continue
        records.append({
            "tool_name": "masscan",
            "target": addr,
            "result": "success",
            "action_class": "read",
            "attack": {"tactic": "TA0007", "technique": "T1046",
                       "sub_technique": None, "attack_version": "15"},
            "finished_at": _now(),
            "parsed": {"open_ports": open_ports},
        })
    return records


def parse_httpx_jsonl(raw: bytes) -> list[dict]:
    """httpx -json(-jsonl) 출력 → 살아있는 웹 서비스 레코드(호스트 단위).
    ATT&CK: T1595(능동 스캐닝) — 웹 표면 프로빙."""
    by_host: dict[str, list] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = rec.get("host") or rec.get("input") or "unknown"
        tech = rec.get("tech") or rec.get("technologies") or []
        by_host.setdefault(host, []).append({
            "url": rec.get("url"),
            "status_code": rec.get("status_code") or rec.get("status-code"),
            "title": rec.get("title"),
            "webserver": rec.get("webserver"),
            "tech": tech,
        })
    records = []
    for host, probes in by_host.items():
        records.append({
            "tool_name": "httpx",
            "target": host,
            "result": "success",
            "action_class": "read",
            "attack": {"tactic": "TA0043", "technique": "T1595",
                       "sub_technique": None, "attack_version": "15"},
            "finished_at": _now(),
            "parsed": {"probes": probes},
        })
    return records


def parse_gobuster(raw: bytes) -> list[dict]:
    """gobuster(dir) 출력 → 발견된 경로 레코드.

    두 형식을 지원한다:
      - JSON: 항목에 url이 있으면 그 호스트로 대상 판정.
      - 텍스트: '/path (Status: 200) [Size: 123]' 라인. 대상 호스트가 출력에 없으므로
        target=None으로 두고, ingest의 --target(default_target)로 채운다.
    ATT&CK: T1595(능동 스캐닝) — 콘텐츠/디렉터리 열거."""
    text = raw.decode("utf-8", errors="replace")
    paths: list[dict] = []
    host = None

    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            doc = json.loads(text)
            items = doc.get("results", doc) if isinstance(doc, dict) else doc
            for it in items or []:
                url = it.get("url") or it.get("path")
                paths.append({"path": it.get("path") or url,
                              "status": it.get("status") or it.get("status_code"),
                              "size": it.get("size") or it.get("length")})
                if not host and it.get("url"):
                    from urllib.parse import urlparse
                    host = urlparse(it["url"]).hostname
        except json.JSONDecodeError:
            pass
    if not paths:
        # 텍스트 형식: '/admin (Status: 301) [Size: 169]'
        line_re = re.compile(r"^(?P<path>/\S*)\s*\(Status:\s*(?P<status>\d+)\)"
                             r"(?:\s*\[Size:\s*(?P<size>\d+)\])?")
        for line in text.splitlines():
            m = line_re.match(line.strip())
            if m:
                paths.append({"path": m.group("path"),
                              "status": int(m.group("status")),
                              "size": int(m.group("size")) if m.group("size") else None})

    if not paths:
        return []
    return [{
        "tool_name": "gobuster",
        "target": host,        # None이면 ingest가 --target으로 채움
        "result": "success",
        "action_class": "read",
        "attack": {"tactic": "TA0043", "technique": "T1595",
                   "sub_technique": None, "attack_version": "15"},
        "finished_at": _now(),
        "parsed": {"paths": paths},
    }]


# 도구 이름 → 파서 (전부 '이미 생성된 출력 파일'을 읽기만 한다 — 도구 실행 X)
PARSERS = {
    "nmap": parse_nmap_xml,
    "nuclei": parse_nuclei_jsonl,
    "masscan": parse_masscan_xml,
    "httpx": parse_httpx_jsonl,
    "gobuster": parse_gobuster,
}
