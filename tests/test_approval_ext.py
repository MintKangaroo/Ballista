"""승인 워크플로 강화 테스트 — TTL 만료 · N-of-M 다중 승인 · 알림 훅."""

from __future__ import annotations

from ballista.policy.approval import ApprovalStore, require_approval_or_raise
from ballista.policy.action import Action
from ballista.attack.refs import AttackRef


def _action(aid="act-x"):
    return Action(aid, AttackRef("TA0001", "T1190"), "exploit", "10.20.0.5", {}, "destructive")


def test_ttl_expiry_blocks(tmp_path):
    ap = ApprovalStore(str(tmp_path / "e.db"))
    a = _action()
    ap.request("ENG", a, ttl_seconds=-1)          # 이미 만료된 TTL
    assert ap.status("ENG", "act-x") == "expired"
    assert ap.list_pending("ENG") == []           # 만료는 대기 목록에서 제외
    # 만료 요청은 승인해도 approved가 되지 않음
    res = ap.decide(_rid(ap), "보안팀장", approved=True)
    assert res["status"] == "expired"
    try:
        require_approval_or_raise(ap, "ENG", a)
        assert False, "만료 요청이 통과됨"
    except PermissionError:
        pass


def _rid(ap: ApprovalStore) -> str:
    return ap._db.execute("SELECT request_id FROM approvals LIMIT 1").fetchone()[0]


def test_n_of_m_quorum(tmp_path):
    ap = ApprovalStore(str(tmp_path / "e.db"))
    a = _action()
    rid = ap.request("ENG", a, quorum=2)
    # 첫 승인 → 아직 pending
    r1 = ap.decide(rid, "승인자A", approved=True)
    assert r1["status"] == "pending" and r1["approvals"] == 1
    assert ap.status("ENG", "act-x") == "pending"
    # 같은 승인자 재승인은 카운트 안 됨
    r_dup = ap.decide(rid, "승인자A", approved=True)
    assert r_dup["approvals"] == 1
    # 두 번째 서로 다른 승인자 → approved
    r2 = ap.decide(rid, "승인자B", approved=True)
    assert r2["status"] == "approved" and r2["approvals"] == 2
    require_approval_or_raise(ap, "ENG", a)       # 통과(예외 없음)


def test_quorum_deny_wins(tmp_path):
    ap = ApprovalStore(str(tmp_path / "e.db"))
    a = _action()
    rid = ap.request("ENG", a, quorum=3)
    ap.decide(rid, "승인자A", approved=True)
    ap.decide(rid, "승인자B", approved=False)      # 한 명 거부
    assert ap.status("ENG", "act-x") == "denied"


def test_notifier_called(tmp_path):
    events = []
    ap = ApprovalStore(str(tmp_path / "e.db"), notifier=events.append)
    a = _action()
    rid = ap.request("ENG", a, quorum=1)
    ap.decide(rid, "보안팀장", approved=True)
    kinds = [e["kind"] for e in events]
    assert kinds == ["request", "decision"]
    assert events[-1]["status"] == "approved"


def test_notifier_failure_does_not_break(tmp_path):
    def boom(_event):
        raise RuntimeError("웹훅 다운")
    ap = ApprovalStore(str(tmp_path / "e.db"), notifier=boom)
    a = _action()
    rid = ap.request("ENG", a)                    # 알림 실패해도 예외 전파 안 됨
    res = ap.decide(rid, "보안팀장", approved=True)
    assert res["status"] == "approved"


def test_backward_compat_single_approver(tmp_path):
    """quorum 기본값 1 — 기존 단일 승인 흐름 유지."""
    ap = ApprovalStore(str(tmp_path / "e.db"))
    a = _action()
    rid = ap.request("ENG", a)
    ap.decide(rid, "보안팀장", approved=True)
    assert ap.status("ENG", "act-x") == "approved"
