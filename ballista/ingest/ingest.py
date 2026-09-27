"""수집 어댑터.

손으로 돌린 도구의 원본 출력 파일을 읽어 evidence 체인에 기록한다.
- 파서로 레코드 추출 (attack 매핑·결과·대상 포함)
- 수집된 대상이 스코프 안인지 검증 (밖이면 그 레코드는 거부)
- 운용자·원본 해시·수집 시각을 붙여 append-only 체인에 기록

익스플로잇 실행과 무관 — 이미 나온 결과를 읽어 기록·매핑만 한다.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .parsers import PARSERS, sha256
from ..evidence.store import EvidenceStore


def ingest_file(store: EvidenceStore, scope, tool: str, path: str,
                operator: str, action_prefix: str = "ing") -> dict:
    """도구 출력 파일 하나를 수집. 요약 dict 반환."""
    if tool not in PARSERS:
        raise ValueError(f"지원하지 않는 도구: {tool} (지원: {', '.join(PARSERS)})")

    with open(path, "rb") as f:
        raw = f.read()
    raw_hash = sha256(raw)

    records = PARSERS[tool](raw)
    ingested, rejected = 0, 0
    ingested_at = datetime.now(timezone.utc).isoformat()

    for i, rec in enumerate(records):
        target = rec.get("target", "")
        # 스코프 밖 대상은 기록하되 거부로 표시 (감사 목적)
        in_scope = scope.is_target_in_scope(target)
        rec = dict(rec)
        rec["action_id"] = f"{action_prefix}-{tool}-{i+1:03d}"
        rec["operator"] = operator
        rec["ingested_at"] = ingested_at
        rec["source_file"] = path
        rec["raw_output_sha256"] = raw_hash
        if not in_scope:
            rec["result"] = "rejected"
            rec["reason"] = f"target out of scope: {target}"
            rejected += 1
        else:
            ingested += 1
        store.append(scope.engagement_id, rec)

    return {"tool": tool, "records": len(records),
            "ingested": ingested, "rejected": rejected,
            "raw_sha256": raw_hash, "operator": operator}
