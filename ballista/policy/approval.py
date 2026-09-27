"""승인 게이트 (Approval Gate).

INV-5: destructive 행위는 사람 승인 또는 사전 서명된 허용 없이는 실행되지 않는다.
이 모듈은 그 '사람 승인'을 실무형으로 강제한다:
- Policy가 REQUIRE_APPROVAL을 내면 액션이 승인 대기 큐에 쌓인다(pending).
- 사람이 CLI로 승인/거부하면 상태가 바뀌고, 승인 사실이 감사 로그로 남는다.
- run()은 승인된 액션에 대해서만 진행된다(승인 없이는 실행 불가).

승인 상태는 evidence.db 안의 별도 테이블에 저장하고, 승인/거부 사실 자체는
evidence 해시 체인에도 감사 레코드로 남긴다(누가·언제 승인했는지 위·변조 불가).
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone


class ApprovalStore:
    def __init__(self, db_path: str = "evidence.db"):
        self._db = sqlite3.connect(db_path)
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS approvals(
                   request_id    TEXT PRIMARY KEY,
                   engagement_id TEXT NOT NULL,
                   action_id     TEXT NOT NULL,
                   summary       TEXT,
                   status        TEXT NOT NULL,   -- pending | approved | denied
                   approver      TEXT,
                   requested_at  TEXT NOT NULL,
                   decided_at    TEXT,
                   UNIQUE(engagement_id, action_id)
               )"""
        )
        self._db.commit()

    def request(self, engagement_id: str, action) -> str:
        """승인 요청 등록(idempotent). 이미 있으면 기존 request_id 반환."""
        row = self._db.execute(
            "SELECT request_id FROM approvals WHERE engagement_id=? AND action_id=?",
            (engagement_id, action.action_id)).fetchone()
        if row:
            return row[0]
        rid = "apr-" + uuid.uuid4().hex[:8]
        summary = (f"{action.tool_name} → {action.target} "
                   f"[{action.attack.id}] class={action.action_class}")
        self._db.execute(
            "INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)",
            (rid, engagement_id, action.action_id, summary, "pending", None,
             datetime.now(timezone.utc).isoformat(), None))
        self._db.commit()
        return rid

    def decide(self, request_id: str, approver: str, approved: bool) -> dict | None:
        """승인/거부 처리. 대상 요청 정보를 반환(감사 기록용), 없으면 None."""
        row = self._db.execute(
            "SELECT engagement_id, action_id, summary FROM approvals WHERE request_id=?",
            (request_id,)).fetchone()
        if not row:
            return None
        status = "approved" if approved else "denied"
        self._db.execute(
            "UPDATE approvals SET status=?, approver=?, decided_at=? WHERE request_id=?",
            (status, approver, datetime.now(timezone.utc).isoformat(), request_id))
        self._db.commit()
        return {"request_id": request_id, "engagement_id": row[0],
                "action_id": row[1], "summary": row[2], "status": status,
                "approver": approver}

    def status(self, engagement_id: str, action_id: str) -> str | None:
        row = self._db.execute(
            "SELECT status FROM approvals WHERE engagement_id=? AND action_id=?",
            (engagement_id, action_id)).fetchone()
        return row[0] if row else None

    def list_pending(self, engagement_id: str | None = None) -> list[dict]:
        if engagement_id:
            cur = self._db.execute(
                "SELECT request_id, action_id, summary, requested_at FROM approvals "
                "WHERE status='pending' AND engagement_id=? ORDER BY requested_at",
                (engagement_id,))
        else:
            cur = self._db.execute(
                "SELECT request_id, action_id, summary, requested_at FROM approvals "
                "WHERE status='pending' ORDER BY requested_at")
        return [{"request_id": r[0], "action_id": r[1], "summary": r[2],
                 "requested_at": r[3]} for r in cur]


def require_approval_or_raise(approvals: ApprovalStore, engagement_id: str, action) -> None:
    """승인 없이 실행되는 것을 코드 레벨에서 막는 가드.
    run() 호출 직전에 부르며, 승인되지 않았으면 예외를 던진다."""
    st = approvals.status(engagement_id, action.action_id)
    if st != "approved":
        raise PermissionError(
            f"'{action.action_id}'은(는) 승인되지 않았습니다(status={st}). 실행 불가.")
