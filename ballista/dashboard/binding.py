"""Dashboard 바인딩 계층.

evidence 체인 + reporter 출력을 대시보드(docs/dashboard.html)가 그대로 소비하는
JSON으로 변환한다. 순수 집계·직렬화 계층 — 공격 실행과 무관하다.

산출 JSON 구조(대시보드 표시 배열에 1:1 대응):
  { engagement, KPI, KILLCHAIN, FEED, GAPS, VULNS, SCOPE }

FEED의 서사(what/why/atk/def)는 여기서 기법·결과 기반 템플릿으로 채운다.
나중에 방어지향 LLM 어시스턴트를 붙이면 이 서사를 evidence 기반으로 자동 생성/보강할 수 있다.
"""

from __future__ import annotations

import json
from datetime import datetime

from ..reporter.reporter import coverage_summary, detection_gaps

# ── ATT&CK 참조(정적 사전) ──────────────────────────────────────────────
TACTICS = [
    ("TA0043", "Reconnaissance",     "--recon"),
    ("TA0007", "Discovery",          "--recon"),
    ("TA0001", "Initial Access",     "--exploit"),
    ("TA0006", "Credential Access",  "--cred"),
    ("TA0008", "Lateral Movement",   "--lateral"),
    ("TA0040", "Impact",             "--impact"),
]

ATTACK_NAMES = {
    "T1046": "네트워크 서비스 탐지",
    "T1018": "원격 시스템 탐지",
    "T1595.002": "능동 스캐닝(취약점 스캔)",
    "T1190": "공개 서비스 취약점 악용",
    "T1003": "OS 자격증명 덤프",
    "T1021.002": "원격 서비스(SMB 관리 공유)",
    "T1486": "영향 목적 데이터 암호화",
}

NARRATIVE = {
    "T1046": {"label": "서비스 탐지",
              "what": "대상 네트워크에서 어떤 서비스(열린 포트)가 돌고 있는지 파악했습니다. 공격 표면을 그리는 첫 단계입니다.",
              "def": "다수 포트로의 연결 시도, SYN 스캔 패턴이 신호입니다. 방화벽 로그와 IDS 스캔 탐지로 잡습니다."},
    "T1018": {"label": "호스트 탐지",
              "what": "네트워크 안에 어떤 호스트들이 살아있는지 목록을 파악했습니다.",
              "def": "대량 핑/ARP 요청, 순차적인 IP 접근이 신호입니다."},
    "T1595.002": {"label": "취약점 탐지",
                  "what": "대상 서비스에 알려진 취약점이 있는지 스캔으로 확인했습니다. 뚫은 게 아니라 존재 여부만 점검한 정찰입니다.",
                  "def": "짧은 시간에 여러 경로로 오는 요청, 스캐너 특유의 요청 패턴, 404 급증이 신호입니다. WAF·IDS 스캔 룰로 잡습니다."},
    "T1190": {"label": "초기 접근 확보",
              "what": "외부에 노출된 취약한 서비스를 통해 처음으로 시스템 안에 발판을 마련했습니다. 침투의 시작점입니다.",
              "def": "노출 서비스로 오는 비정상 요청·예외 로그, 취약 버전 사용 여부, 접근 직후 생기는 새 프로세스나 셸이 핵심 신호입니다."},
    "T1003": {"label": "자격증명 확보 시도",
              "what": "시스템에 저장·캐시된 계정 정보를 얻으려는 시도입니다.",
              "def": "민감 프로세스(LSASS 등) 접근, 자격증명 저장소 열람에 탐지 룰이 있어야 합니다. 이 시도가 SIEM에 남는지 점검이 핵심입니다."},
    "T1021.002": {"label": "원격 서비스 이동",
                  "what": "이미 확보한 계정으로 다른 시스템에 정상 프로토콜처럼 접속해 장악 범위를 옆으로 넓힌 행위입니다.",
                  "def": "정상 로그인과 구분이 어렵습니다. 관리 공유(ADMIN$/C$) 접근, 평소 안 쓰던 계정의 원격 로그온(4624 type 3), 짧은 시간 다수 호스트 확산을 상관분석해야 잡힙니다."},
    "T1486": {"label": "금지 기법 차단",
              "what": "데이터를 암호화하는 파괴적 기법(랜섬웨어류)이 시도됐지만 차단됐습니다.",
              "def": "파괴적 기법을 교전에서 원천 배제하는 안전장치입니다. 실제 환경에 손상을 주지 않게 합니다."},
    "scope_deny": {"label": "범위 밖 대상 차단",
                   "what": "허용 범위 밖 대상으로 향하는 행위가 시도됐지만, 실행되기 전에 차단됐습니다.",
                   "def": "교전이 계약된 범위를 벗어나지 않도록 보장하는 안전장치입니다. 오탐·실수로 외부를 건드리는 사고를 막습니다."},
    "tech_deny": {"label": "금지 기법 차단",
                  "what": "스코프가 명시적으로 금지한 기법이라 실행되지 않고 차단됐습니다.",
                  "def": "위험 기법을 교전에서 배제하는 통제입니다."},
    "approval": {"label": "승인 대기",
                 "what": "파급이 큰 등급의 행위라 실행되지 않고 사람 승인 대기 상태에서 멈췄습니다.",
                 "def": "민감 행위를 사람이 검토하게 하는 게이트입니다."},
    "auth": {"label": "스코프 서명 검증",
             "what": "교전 시작 전, 서명된 범위 문서(RoE)의 위·변조 여부를 검증했습니다.",
             "def": "모든 행위가 승인된 범위에 암호학적으로 묶여 있음을 보장합니다."},
    "generic": {"label": "행위", "what": "기록된 행위입니다.", "def": "관련 로그를 상관분석해 탐지합니다."},
}

_SEV_MAP = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "low"}


def _tid(rec):
    a = rec.get("attack") or {}
    return a.get("sub_technique") or a.get("technique")

def _hhmmss(rec):
    ts = rec.get("finished_at") or rec.get("recorded_at") or ""
    try:
        return datetime.fromisoformat(ts).strftime("%H:%M:%S")
    except ValueError:
        return ts[11:19] if len(ts) >= 19 else ts

def _kind(rec):
    result = rec.get("result")
    reason = (rec.get("reason") or "").lower()
    if rec.get("tool_name") == "authorization" or result == "info":
        return "auth"
    if result == "blocked":
        if "out of scope" in reason:
            return "scope_deny"
        if "approval" in reason:
            return "approval"
        return "tech_deny"
    return _tid(rec) or "generic"

def _rc(rec, kind):
    if kind == "auth":
        return "info"
    if kind == "approval":
        return "approval"
    return "success" if rec.get("result") == "success" else "blocked"

def _narr(kind):
    return NARRATIVE.get(kind, NARRATIVE["generic"])

def _why(rec, kind):
    if kind == "auth":
        return "이 검증을 통과해야만 이후 모든 행위가 가능합니다(INV-3)."
    if kind == "scope_deny":
        return "대상이 허용 범위(CIDR/호스트)에 없어 deny-by-default로 차단됐습니다."
    if kind == "tech_deny":
        return "스코프의 금지 기법 목록에 걸려 Policy가 차단했습니다."
    if kind == "approval":
        return "파급이 큰 등급이라 사람 승인이 필요해 자동 진행이 멈췄습니다."
    cls = rec.get("action_class", "read")
    return f"대상이 범위 안이고 허용 기법·등급(action_class: {cls})이라 통과해 실행됐습니다."


def _feed(records):
    out = []
    for rec in reversed(records):
        kind = _kind(rec)
        tid = _tid(rec)
        narr = _narr(kind)
        target = rec.get("target", "")
        if kind in ("auth", "scope_deny"):
            atk = "해당 없음 — 통제 계층(안전장치)입니다."
        elif tid:
            atk = f"{tid} — {ATTACK_NAMES.get(tid, '기법')}."
        else:
            atk = "해당 없음."
        tool = rec.get("tool_name", "")
        d2 = f"{tool} · {tid}" if tid else (tool or "authorization")
        out.append({
            "tm": _hhmmss(rec),
            "d1": narr["label"] + (f" → {target}" if target else ""),
            "d2": d2,
            "rc": _rc(rec, kind),
            "cls": rec.get("action_class", ""),
            "what": narr["what"],
            "why": _why(rec, kind),
            "atk": atk,
            "def": narr["def"],
        })
    return out

def _killchain(records):
    agg = {tid: {"att": 0, "ok": 0} for tid, _, _ in TACTICS}
    for rec in records:
        tac = (rec.get("attack") or {}).get("tactic")
        if tac in agg:
            agg[tac]["att"] += 1
            if rec.get("result") == "success":
                agg[tac]["ok"] += 1
    return [{"t": nm, "id": tid, "c": cvar, "att": agg[tid]["att"], "ok": agg[tid]["ok"]}
            for tid, nm, cvar in TACTICS]

def _findings(records):
    out = []
    for rec in records:
        parsed = rec.get("parsed") or {}
        for f in parsed.get("findings", []):
            sev = _SEV_MAP.get((f.get("severity") or "").lower(), "low")
            host = (f.get("host") or "").replace("https://", "").replace("http://", "").split("/")[0]
            out.append({"sev": sev, "v1": f.get("name") or "탐지된 취약점",
                        "v2": f.get("template_id") or "", "host": host})
    order = {"crit": 0, "high": 1, "med": 2, "low": 3}
    out.sort(key=lambda x: order.get(x["sev"], 9))
    return out

def _gaps(records, summary, detected):
    raw = detection_gaps(summary, detected)
    by_tid = {}
    for rec in records:
        if rec.get("result") == "success":
            by_tid[_tid(rec)] = rec
    out = []
    for g in raw:
        rep = by_tid.get(g["id"])
        host = rep.get("target", "") if rep else ""
        name = ATTACK_NAMES.get(g["id"], g["id"])
        out.append({"id": g["id"], "txt": f"{name} 성공했으나 탐지 이벤트 없음",
                    "meta": f"{host} · {_hhmmss(rep)}" if rep else "-"})
    return out

def _kpis(records, gaps, chain_ok, findings):
    executed = len(records)
    hosts = sorted({r.get("target", "") for r in records
                    if r.get("result") == "success"
                    and r.get("action_class") in ("modify", "destructive")})
    success_paths = len(hosts)
    crit = sum(1 for f in findings if f["sev"] == "crit")
    high = sum(1 for f in findings if f["sev"] == "high")
    return [
        {"lab": "EXECUTED ACTIONS", "val": executed, "u": "", "meta": f"기록 {executed}건", "kc": "--amber"},
        {"lab": "SUCCESSFUL PATHS", "val": success_paths, "u": "",
         "meta": (" → ".join(h for h in hosts if h) if hosts else "없음"), "kc": "--allow"},
        {"lab": "FINDINGS", "val": len(findings), "u": "",
         "meta": f"critical {crit} · high {high}", "metaCrit": crit > 0, "kc": "--cred"},
        {"lab": "DETECTION GAPS", "val": len(gaps), "u": "",
         "meta": "미탐지 성공 기법", "metaCrit": len(gaps) > 0, "kc": "--deny"},
        {"lab": "CHAIN INTEGRITY", "val": "OK" if chain_ok else "FAIL", "u": "",
         "meta": f"{executed}/{executed} verified" if chain_ok else "위반 감지!",
         "kc": "--allow" if chain_ok else "--deny"},
    ]

def _scope_section(scope):
    raw = getattr(scope, "raw", {}) or {}
    approver = (raw.get("engagement") or {}).get("authorized_by", "-")
    return {
        "time_window": "active" if scope.is_within_time_window() else "expired",
        "max_class": scope.max_action_class,
        "approver": approver,
        "signature": "Ed25519 \u2713",
        "in_scope": list(scope.in_scope_cidrs) + list(scope.in_scope_hosts),
        "out_of_scope": list(scope.out_of_scope_hosts),
    }


def build_attack_path_graph(records):
    """성공 경로를 노드/엣지 그래프로 요약.

    노드: 대상 호스트, 참조된 자격증명(cred_ref), 진입점(entry).
    엣지: 성공한 기법이 어느 노드에서 어느 호스트로 향했는지(기법 라벨).
    프런트(dashboard.html)가 그대로 소비하는 형태 — 순수 집계, 실행 없음.
    """
    nodes: dict[str, dict] = {"entry": {"id": "entry", "kind": "entry", "label": "진입점"}}
    edges = []
    for rec in records:
        if rec.get("result") != "success":
            continue
        tid = _tid(rec)
        if not tid:
            continue
        target = rec.get("target") or ""
        params = rec.get("params") or {}
        # 대상 호스트 노드
        if target:
            nodes.setdefault(target, {"id": target, "kind": "host", "label": target})
        # 자격증명 참조 노드
        cred = params.get("cred_ref")
        if cred:
            nodes.setdefault(cred, {"id": cred, "kind": "credential", "label": cred})
        # 출발 노드: 명시된 source/from 호스트가 있으면 그 호스트, 없으면 진입점
        src = params.get("source") or params.get("from")
        if src:
            nodes.setdefault(src, {"id": src, "kind": "host", "label": src})
        src_id = src or (cred or "entry")
        if target:
            edges.append({
                "from": src_id, "to": target,
                "technique": tid, "label": ATTACK_NAMES.get(tid, tid),
                "tool": rec.get("tool_name", ""),
            })
    return {"nodes": list(nodes.values()), "edges": edges}


def build_dashboard_data(store, scope, engagement_id, detected_technique_ids=None):
    records = list(store.records(engagement_id))
    summary = coverage_summary(store, engagement_id)
    detected = detected_technique_ids or set()
    findings = _findings(records)
    gaps = _gaps(records, summary, detected)
    chain_ok = store.verify_chain(engagement_id)
    raw = getattr(scope, "raw", {}) or {}
    return {
        "engagement": {
            "id": engagement_id,
            "name": (raw.get("engagement") or {}).get("name", ""),
            "scope_signed": True,
            "window_active": scope.is_within_time_window(),
            "max_class": scope.max_action_class,
        },
        "KPI": _kpis(records, gaps, chain_ok, findings),
        "KILLCHAIN": _killchain(records),
        "FEED": _feed(records),
        "GAPS": gaps,
        "VULNS": findings,
        "GRAPH": build_attack_path_graph(records),
        "SCOPE": _scope_section(scope),
    }


def export_dashboard_json(store, scope, engagement_id, path, detected_technique_ids=None):
    data = build_dashboard_data(store, scope, engagement_id, detected_technique_ids)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path
