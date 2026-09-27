"""승인 게이트 흐름 증명."""
import os, tempfile
from ballista.policy.approval import ApprovalStore, require_approval_or_raise
from ballista.policy.action import Action
from ballista.attack.refs import AttackRef


def _action():
    return Action("act-x", AttackRef("TA0001", "T1190"), "exploit", "10.20.0.5", {}, "destructive")


def test_approval_flow():
    fd, p = tempfile.mkstemp(suffix=".db"); os.close(fd)
    try:
        ap = ApprovalStore(p)
        a = _action()
        assert ap.status("ENG", "act-x") is None
        rid = ap.request("ENG", a)
        assert ap.status("ENG", "act-x") == "pending"
        assert ap.request("ENG", a) == rid            # idempotent
        assert len(ap.list_pending("ENG")) == 1
        ap.decide(rid, "보안팀장", approved=True)
        assert ap.status("ENG", "act-x") == "approved"
        assert ap.list_pending("ENG") == []
    finally:
        os.remove(p)


def test_guard_blocks_without_approval():
    fd, p = tempfile.mkstemp(suffix=".db"); os.close(fd)
    try:
        ap = ApprovalStore(p)
        a = _action()
        # 승인 전 → 가드가 예외
        try:
            require_approval_or_raise(ap, "ENG", a)
            assert False, "승인 없이 통과됨"
        except PermissionError:
            pass
        # 승인 후 → 통과
        rid = ap.request("ENG", a)
        ap.decide(rid, "보안팀장", approved=True)
        require_approval_or_raise(ap, "ENG", a)         # 예외 없어야 함
    finally:
        os.remove(p)


def test_denied_stays_blocked():
    fd, p = tempfile.mkstemp(suffix=".db"); os.close(fd)
    try:
        ap = ApprovalStore(p)
        a = _action()
        rid = ap.request("ENG", a)
        ap.decide(rid, "보안팀장", approved=False)
        assert ap.status("ENG", "act-x") == "denied"
    finally:
        os.remove(p)
