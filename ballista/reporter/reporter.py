"""Reporter: evidence 체인에서 ATT&CK 커버리지 요약과 방어 대조 산출물 생성.

전부 사후 분석·리포팅이다. 공격 실행 없음.
- coverage_summary : 기법별 시도/성공 집계
- navigator_layer  : MITRE ATT&CK Navigator가 읽는 layer.json
- detection_gaps   : 성공했으나 탐지되지 않은 기법(= 탐지 공백)

detection_gaps가 이 프로젝트를 방어 조직용 도구로 만드는 핵심이다.
SOC/SIEM에서 뽑은 "탐지된 technique_id 집합"과 조인해 공백을 산출한다.

프로젝트 배치: ballista/reporter/reporter.py
의존: ballista/evidence/store.py 의 EvidenceStore
"""

from __future__ import annotations

from collections import defaultdict


def coverage_summary(store, engagement_id: str, attack_version: str = "15") -> dict:
    """evidence를 기법 단위로 집계."""
    agg: dict[str, dict] = defaultdict(
        lambda: {"attempts": 0, "successes": 0, "first_seen": None, "last_seen": None}
    )
    for rec in store.records(engagement_id):
        attack = rec.get("attack")
        if not attack:
            continue
        tid = attack.get("sub_technique") or attack.get("technique")
        a = agg[tid]
        a["attempts"] += 1
        if rec.get("result") == "success":
            a["successes"] += 1
        ts = rec.get("finished_at") or rec.get("recorded_at")
        if ts:
            if a["first_seen"] is None or ts < a["first_seen"]:
                a["first_seen"] = ts
            if a["last_seen"] is None or ts > a["last_seen"]:
                a["last_seen"] = ts
    return {
        "engagement_id": engagement_id,
        "attack_version": attack_version,
        "techniques": [{"id": k, **v} for k, v in sorted(agg.items())],
    }


def navigator_layer(summary: dict, name: str | None = None) -> dict:
    """커버리지 요약 → ATT&CK Navigator layer JSON.
    성공률(0~100)을 score로 매핑해 색으로 시각화된다."""
    techniques = []
    for t in summary["techniques"]:
        score = round(100 * t["successes"] / t["attempts"]) if t["attempts"] else 0
        techniques.append({
            "techniqueID": t["id"],
            "score": score,
            "comment": f'{t["successes"]}/{t["attempts"]} 성공',
        })
    return {
        "name": name or f'{summary["engagement_id"]} executed techniques',
        "versions": {"attack": summary["attack_version"],
                     "navigator": "5.0.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Ballista가 실행한 기법 커버리지",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
    }


def detection_gaps(summary: dict, detected_technique_ids: set[str]) -> list[dict]:
    """성공했지만 방어 탐지에 걸리지 않은 기법 목록.

    detected_technique_ids : SOC/SIEM에서 같은 교전 시간창에 탐지된
                             ATT&CK technique/sub-technique ID 집합.
    반환 : 탐지 공백 기법 (우선 보완 대상)
    """
    gaps = []
    for t in summary["techniques"]:
        if t["successes"] > 0 and t["id"] not in detected_technique_ids:
            gaps.append({
                "id": t["id"],
                "successes": t["successes"],
                "first_seen": t["first_seen"],
                "last_seen": t["last_seen"],
            })
    return gaps
