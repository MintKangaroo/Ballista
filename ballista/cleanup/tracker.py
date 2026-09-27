"""Cleanup/롤백 추적.

교전 중 운용자가 생성한 아티팩트(세션·계정·업로드 파일·스케줄 작업 등)를 목록화하고,
교전 종료 시 회수(reclaim)되었는지 체크리스트로 관리한다. 방치된 백도어/잔여물이
남지 않도록 하는 통제·기록 계층이다(공격 실행과 무관).

승인 게이트와 같은 패턴:
- 가변 상태(pending→reclaimed)는 전용 테이블(cleanup_items)에 저장.
- 등록/회수 '사실'은 evidence 해시 체인에도 감사 레코드로 남긴다(위·변조 불가).

아티팩트 값 자체(예: 계정 비밀번호)는 담지 않는다 — 식별자·위치·회수 방법만 기록한다.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone

from ..evidence.store import EvidenceStore

# 값 유출 방지: 식별자에 비밀번호/해시 등이 들어오지 않도록 힌트(경고용).
_VALUE_HINT_KEYS = ("password", "secret", "hash", "ntlm", "token", "privkey")


class CleanupTracker:
    def __init__(self, db_path: str = "evidence.db"):
        self._db = sqlite3.connect(db_path)
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS cleanup_items(
                   item_id       TEXT PRIMARY KEY,
                   engagement_id TEXT NOT NULL,
                   artifact_type TEXT NOT NULL,   -- session|account|file|scheduled_task|service|other
                   identifier    TEXT NOT NULL,   -- 식별자(값 아님): 계정명·경로·세션ID 등
                   host          TEXT,
                   note          TEXT,            -- 회수 방법 메모
                   created_by    TEXT NOT NULL,
                   status        TEXT NOT NULL,   -- pending | reclaimed
                   created_at    TEXT NOT NULL,
                   reclaimed_by  TEXT,
                   reclaimed_at  TEXT
               )"""
        )
        self._db.commit()
        self._store = EvidenceStore(db_path)

    def register(self, engagement_id: str, artifact_type: str, identifier: str,
                 created_by: str, host: str = "", note: str = "") -> str:
        """생성 아티팩트 등록. 반환: item_id. 등록 사실을 evidence에 감사 기록."""
        item_id = "clp-" + uuid.uuid4().hex[:8]
        now = datetime.now(timezone.utc).isoformat()
        self._db.execute(
            "INSERT INTO cleanup_items(item_id, engagement_id, artifact_type, identifier,"
            " host, note, created_by, status, created_at, reclaimed_by, reclaimed_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (item_id, engagement_id, artifact_type, identifier, host, note,
             created_by, "pending", now, None, None))
        self._db.commit()
        self._store.append(engagement_id, {
            "action_id": item_id, "tool_name": "cleanup", "result": "registered",
            "action_class": "", "target": host,
            "reason": f"{artifact_type}:{identifier} registered by {created_by}",
        })
        return item_id

    def reclaim(self, item_id: str, reclaimed_by: str) -> dict | None:
        """아티팩트 회수 처리. 반환: 항목 dict(없으면 None). 회수 사실을 evidence에 기록."""
        row = self._db.execute(
            "SELECT engagement_id, artifact_type, identifier, host FROM cleanup_items "
            "WHERE item_id=?", (item_id,)).fetchone()
        if not row:
            return None
        engagement_id, atype, ident, host = row
        now = datetime.now(timezone.utc).isoformat()
        self._db.execute(
            "UPDATE cleanup_items SET status='reclaimed', reclaimed_by=?, reclaimed_at=? "
            "WHERE item_id=?", (reclaimed_by, now, item_id))
        self._db.commit()
        self._store.append(engagement_id, {
            "action_id": item_id, "tool_name": "cleanup", "result": "reclaimed",
            "action_class": "", "target": host,
            "reason": f"{atype}:{ident} reclaimed by {reclaimed_by}",
        })
        return {"item_id": item_id, "engagement_id": engagement_id,
                "artifact_type": atype, "identifier": ident, "status": "reclaimed"}

    def list_items(self, engagement_id: str, status: str | None = None) -> list[dict]:
        q = ("SELECT item_id, artifact_type, identifier, host, note, created_by, status,"
             " created_at, reclaimed_by, reclaimed_at FROM cleanup_items WHERE engagement_id=?")
        params = [engagement_id]
        if status:
            q += " AND status=?"; params.append(status)
        q += " ORDER BY created_at"
        cols = ["item_id", "artifact_type", "identifier", "host", "note", "created_by",
                "status", "created_at", "reclaimed_by", "reclaimed_at"]
        return [dict(zip(cols, r)) for r in self._db.execute(q, params)]

    def summary(self, engagement_id: str) -> dict:
        items = self.list_items(engagement_id)
        pending = [i for i in items if i["status"] == "pending"]
        return {"total": len(items), "pending": len(pending),
                "reclaimed": len(items) - len(pending)}

    def checklist_markdown(self, engagement_id: str) -> str:
        """회수 체크리스트(Markdown). 미회수 항목은 [ ], 회수 완료는 [x]."""
        items = self.list_items(engagement_id)
        s = self.summary(engagement_id)
        L = [f"# Cleanup 체크리스트 — {engagement_id}", "",
             f"총 {s['total']}건 · 미회수 {s['pending']} · 회수완료 {s['reclaimed']}", ""]
        if not items:
            L.append("_등록된 아티팩트 없음._")
            return "\n".join(L) + "\n"
        if s["pending"]:
            L.append("> ⚠️ 미회수 아티팩트가 남아 있습니다. 교전 종료 전 회수하세요.")
            L.append("")
        for i in items:
            box = "x" if i["status"] == "reclaimed" else " "
            loc = f" @ {i['host']}" if i["host"] else ""
            note = f" — {i['note']}" if i["note"] else ""
            who = (f" (회수: {i['reclaimed_by']})" if i["status"] == "reclaimed"
                   else f" (생성: {i['created_by']})")
            L.append(f"- [{box}] `{i['item_id']}` **{i['artifact_type']}**: "
                     f"{i['identifier']}{loc}{note}{who}")
        return "\n".join(L) + "\n"


def identifier_looks_like_secret(identifier: str) -> bool:
    """식별자에 비밀값이 섞였을 가능성 경고용(등록 자체는 막지 않음)."""
    low = identifier.lower()
    return any(h in low for h in _VALUE_HINT_KEYS)
