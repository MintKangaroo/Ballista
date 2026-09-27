"""Evidence Store: append-only 해시 체인.

INV-4: 모든 액션은 여기 남는다. 기록 실패 시 실행도 중단(호출부 책임).
공격 실행과 무관한 기록·무결성 인프라다.

각 레코드 해시 = sha256( canonical(record) + prev_hash ).
체인이므로 중간 레코드를 위·변조하면 이후 전부가 깨져 탐지된다.

프로젝트 배치: ballista/evidence/store.py
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

_GENESIS = "0" * 64


def _canonical(obj) -> bytes:
    """결정론적 직렬화 — 키 정렬, 공백 제거. 해시 안정성의 핵심."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, default=str,
    ).encode("utf-8")


def tool_result_to_record(result, *, action_id: str, engagement_id: str,
                          target: str, action_class: str,
                          result_status: str) -> dict:
    """ToolResult(바이너리 output 포함)를 evidence 레코드(JSON 가능)로 변환.

    raw_output은 JSON에 담지 않고 길이/해시만 남긴다. 원본이 필요하면
    별도 blob 저장소에 output_ref로 보관(여기서는 해시로 대체).
    """
    attack = result.attack
    return {
        "action_id": action_id,
        "engagement_id": engagement_id,
        "attack": {
            "tactic": attack.tactic,
            "technique": attack.technique,
            "sub_technique": attack.sub_technique,
            "attack_version": attack.attack_version,
        },
        "tool_name": result.tool,
        "argv": result.argv,
        "target": target,
        "action_class": action_class,
        "result": result_status,             # "success" | "failure" | "error"
        "returncode": result.returncode,
        "raw_output_len": len(result.raw_output or b""),
        "raw_output_sha256": hashlib.sha256(result.raw_output or b"").hexdigest(),
        "parsed": result.parsed,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
    }


class EvidenceStore:
    def __init__(self, db_path: str = "evidence.db"):
        self._db = sqlite3.connect(db_path)
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS evidence(
                   seq           INTEGER PRIMARY KEY AUTOINCREMENT,
                   engagement_id TEXT NOT NULL,
                   record_json   TEXT NOT NULL,
                   prev_hash     TEXT NOT NULL,
                   record_hash   TEXT NOT NULL
               )"""
        )
        self._db.commit()

    def _last_hash(self, engagement_id: str) -> str:
        row = self._db.execute(
            "SELECT record_hash FROM evidence WHERE engagement_id=? "
            "ORDER BY seq DESC LIMIT 1",
            (engagement_id,),
        ).fetchone()
        return row[0] if row else _GENESIS

    def append(self, engagement_id: str, record: dict) -> str:
        """레코드를 체인에 추가하고 record_hash를 반환."""
        record = dict(record)
        record.setdefault("recorded_at", datetime.now(timezone.utc).isoformat())
        prev = self._last_hash(engagement_id)
        record_hash = hashlib.sha256(_canonical(record) + prev.encode()).hexdigest()
        self._db.execute(
            "INSERT INTO evidence(engagement_id, record_json, prev_hash, record_hash) "
            "VALUES(?,?,?,?)",
            (engagement_id, json.dumps(record, ensure_ascii=False, default=str),
             prev, record_hash),
        )
        self._db.commit()
        return record_hash

    def verify_chain(self, engagement_id: str) -> bool:
        """전체 체인을 재해싱해 무결성을 검증."""
        prev = _GENESIS
        for record_json, stored_prev, stored_hash in self._db.execute(
            "SELECT record_json, prev_hash, record_hash FROM evidence "
            "WHERE engagement_id=? ORDER BY seq",
            (engagement_id,),
        ):
            if stored_prev != prev:
                return False
            rec = json.loads(record_json)
            recomputed = hashlib.sha256(_canonical(rec) + prev.encode()).hexdigest()
            if recomputed != stored_hash:
                return False
            prev = stored_hash
        return True

    def records(self, engagement_id: str):
        for (record_json,) in self._db.execute(
            "SELECT record_json FROM evidence WHERE engagement_id=? ORDER BY seq",
            (engagement_id,),
        ):
            yield json.loads(record_json)
