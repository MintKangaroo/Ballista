"""승인 게이트 (Approval Gate).

INV-5: destructive 행위는 사람 승인 또는 사전 서명된 허용 없이는 실행되지 않는다.
이 모듈은 그 '사람 승인'을 실무형으로 강제한다:
- Policy가 REQUIRE_APPROVAL을 내면 액션이 승인 대기 큐에 쌓인다(pending).
- 사람이 CLI로 승인/거부하면 상태가 바뀌고, 승인 사실이 감사 로그로 남는다.
- run()은 승인된 액션에 대해서만 진행된다(승인 없이는 실행 불가).

강화 기능:
- **TTL 만료**: 요청에 ttl_seconds를 주면 그 시간이 지난 pending은 'expired'로 판정되어
  실행이 막힌다(오래된 승인 요청이 방치돼 나중에 통과되는 것을 방지).
- **N-of-M 다중 승인**: quorum(정족수)만큼 서로 다른 승인자가 승인해야 'approved'.
  한 명이라도 거부하면 즉시 'denied'.
- **알림 훅**: 요청/결정 시 notifier(event)를 호출(Slack 웹훅 등 연결용, 실패는 무시).

승인 상태는 evidence.db 안의 별도 테이블에 저장하고, 승인/거부 사실 자체는
evidence 해시 체인에도 감사 레코드로 남긴다(누가·언제 승인했는지 위·변조 불가).
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta, timezone


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ApprovalStore:
    def __init__(self, db_path: str = "evidence.db", notifier=None):
        self._db = sqlite3.connect(db_path)
        self._notifier = notifier
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
                   quorum        INTEGER NOT NULL DEFAULT 1,
                   expires_at    TEXT,
                   UNIQUE(engagement_id, action_id)
               )"""
        )
        # 개별 승인자 결정 기록(N-of-M 집계용). 같은 승인자의 중복 승인은 무시.
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS approval_decisions(
                   request_id TEXT NOT NULL,
                   approver   TEXT NOT NULL,
                   approved   INTEGER NOT NULL,
                   decided_at TEXT NOT NULL,
                   UNIQUE(request_id, approver)
               )"""
        )
        self._migrate()
        self._db.commit()

    def _migrate(self) -> None:
        """구버전 DB(quorum/expires_at 컬럼 없음)를 안전하게 업그레이드."""
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(approvals)")}
        if "quorum" not in cols:
            self._db.execute("ALTER TABLE approvals ADD COLUMN quorum INTEGER NOT NULL DEFAULT 1")
        if "expires_at" not in cols:
            self._db.execute("ALTER TABLE approvals ADD COLUMN expires_at TEXT")

    def _notify(self, event: dict) -> None:
        if self._notifier:
            try:
                self._notifier(event)
            except Exception:
                pass  # 알림 실패는 승인 흐름을 막지 않는다

    def request(self, engagement_id: str, action, ttl_seconds: int | None = None,
                quorum: int = 1) -> str:
        """승인 요청 등록(idempotent). 이미 있으면 기존 request_id 반환.

        ttl_seconds : 이 시간(초) 안에 정족수를 못 채우면 만료.
        quorum      : 필요한 서로 다른 승인자 수(N-of-M).
        """
        row = self._db.execute(
            "SELECT request_id FROM approvals WHERE engagement_id=? AND action_id=?",
            (engagement_id, action.action_id)).fetchone()
        if row:
            return row[0]
        rid = "apr-" + uuid.uuid4().hex[:8]
        summary = (f"{action.tool_name} → {action.target} "
                   f"[{action.attack.id}] class={action.action_class}")
        now = _now()
        expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat() if ttl_seconds else None
        self._db.execute(
            "INSERT INTO approvals(request_id, engagement_id, action_id, summary, status,"
            " approver, requested_at, decided_at, quorum, expires_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (rid, engagement_id, action.action_id, summary, "pending", None,
             now.isoformat(), None, max(1, quorum), expires_at))
        self._db.commit()
        self._notify({"kind": "request", "engagement_id": engagement_id,
                      "action_id": action.action_id, "request_id": rid,
                      "summary": summary, "status": "pending", "quorum": max(1, quorum)})
        return rid

    def _row(self, request_id: str):
        return self._db.execute(
            "SELECT engagement_id, action_id, summary, status, quorum, expires_at "
            "FROM approvals WHERE request_id=?", (request_id,)).fetchone()

    @staticmethod
    def _expired(status: str, expires_at: str | None) -> bool:
        if status != "pending" or not expires_at:
            return False
        try:
            return _now() > datetime.fromisoformat(expires_at)
        except ValueError:
            return False

    def _approved_count(self, request_id: str) -> int:
        return self._db.execute(
            "SELECT COUNT(*) FROM approval_decisions WHERE request_id=? AND approved=1",
            (request_id,)).fetchone()[0]

    def decide(self, request_id: str, approver: str, approved: bool) -> dict | None:
        """승인/거부 처리. 대상 요청 정보를 반환(감사 기록용), 없으면 None.

        N-of-M: quorum만큼 서로 다른 승인자가 approved해야 status='approved'.
        거부는 한 명이라도 나오면 즉시 'denied'. TTL 만료 요청은 결정 불가.
        """
        row = self._row(request_id)
        if not row:
            return None
        engagement_id, action_id, summary, status, quorum, expires_at = row

        if self._expired(status, expires_at):
            self._db.execute("UPDATE approvals SET status='expired' WHERE request_id=?",
                             (request_id,))
            self._db.commit()
            result = {"request_id": request_id, "engagement_id": engagement_id,
                      "action_id": action_id, "summary": summary, "status": "expired",
                      "approver": approver}
            self._notify({"kind": "decision", **result})
            return result

        now = _now().isoformat()
        # 개별 결정 기록(중복 승인자는 무시)
        self._db.execute(
            "INSERT OR IGNORE INTO approval_decisions(request_id, approver, approved, decided_at)"
            " VALUES(?,?,?,?)", (request_id, approver, 1 if approved else 0, now))

        if not approved:
            new_status = "denied"
        else:
            new_status = "approved" if self._approved_count(request_id) >= quorum else "pending"

        self._db.execute(
            "UPDATE approvals SET status=?, approver=?, decided_at=? WHERE request_id=?",
            (new_status, approver, now, request_id))
        self._db.commit()

        result = {"request_id": request_id, "engagement_id": engagement_id,
                  "action_id": action_id, "summary": summary, "status": new_status,
                  "approver": approver, "approvals": self._approved_count(request_id),
                  "quorum": quorum}
        self._notify({"kind": "decision", **result})
        return result

    def status(self, engagement_id: str, action_id: str) -> str | None:
        row = self._db.execute(
            "SELECT status, expires_at FROM approvals WHERE engagement_id=? AND action_id=?",
            (engagement_id, action_id)).fetchone()
        if not row:
            return None
        status, expires_at = row
        return "expired" if self._expired(status, expires_at) else status

    def list_pending(self, engagement_id: str | None = None) -> list[dict]:
        if engagement_id:
            cur = self._db.execute(
                "SELECT request_id, action_id, summary, requested_at, quorum, expires_at FROM approvals "
                "WHERE status='pending' AND engagement_id=? ORDER BY requested_at",
                (engagement_id,))
        else:
            cur = self._db.execute(
                "SELECT request_id, action_id, summary, requested_at, quorum, expires_at FROM approvals "
                "WHERE status='pending' ORDER BY requested_at")
        out = []
        for r in cur:
            if self._expired("pending", r[5]):
                continue  # 만료된 것은 대기 목록에서 제외
            out.append({"request_id": r[0], "action_id": r[1], "summary": r[2],
                        "requested_at": r[3], "quorum": r[4],
                        "approvals": self._approved_count(r[0])})
        return out


def require_approval_or_raise(approvals: ApprovalStore, engagement_id: str, action) -> None:
    """승인 없이 실행되는 것을 코드 레벨에서 막는 가드.
    run() 호출 직전에 부르며, 승인되지 않았으면 예외를 던진다.
    (pending·denied·expired 모두 실행 불가 — 오직 approved만 통과)"""
    st = approvals.status(engagement_id, action.action_id)
    if st != "approved":
        raise PermissionError(
            f"'{action.action_id}'은(는) 승인되지 않았습니다(status={st}). 실행 불가.")
