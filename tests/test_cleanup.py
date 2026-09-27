"""Cleanup/롤백 추적 테스트 — 등록·회수·체크리스트·evidence 감사 기록."""

from __future__ import annotations

from ballista.cleanup.tracker import CleanupTracker, identifier_looks_like_secret
from ballista.evidence.store import EvidenceStore


def test_register_and_reclaim(tmp_path):
    db = str(tmp_path / "e.db")
    tr = CleanupTracker(db)
    iid = tr.register("ENG", "account", "svc-temp", created_by="윤지창",
                      host="app01", note="net user /del")
    assert iid.startswith("clp-")
    assert tr.summary("ENG") == {"total": 1, "pending": 1, "reclaimed": 0}

    res = tr.reclaim(iid, "홍길동")
    assert res["status"] == "reclaimed"
    assert tr.summary("ENG") == {"total": 1, "pending": 0, "reclaimed": 1}
    assert tr.reclaim("clp-nope", "x") is None


def test_audit_written_to_evidence_chain(tmp_path):
    db = str(tmp_path / "e.db")
    tr = CleanupTracker(db)
    iid = tr.register("ENG", "file", "/tmp/impl", created_by="op")
    tr.reclaim(iid, "op2")

    store = EvidenceStore(db)
    recs = [r for r in store.records("ENG") if r.get("tool_name") == "cleanup"]
    assert [r["result"] for r in recs] == ["registered", "reclaimed"]
    assert store.verify_chain("ENG")          # 감사 기록 후에도 체인 무결


def test_checklist_markdown(tmp_path):
    tr = CleanupTracker(str(tmp_path / "e.db"))
    a = tr.register("ENG", "session", "sess-1", created_by="op")
    tr.register("ENG", "account", "bkdoor", created_by="op")
    tr.reclaim(a, "op")

    md = tr.checklist_markdown("ENG")
    assert "미회수 1" in md and "회수완료 1" in md
    assert "- [x]" in md          # 회수된 항목
    assert "- [ ]" in md          # 미회수 항목
    assert "미회수 아티팩트가 남아" in md   # 경고


def test_list_filter_and_empty_checklist(tmp_path):
    tr = CleanupTracker(str(tmp_path / "e.db"))
    assert "등록된 아티팩트 없음" in tr.checklist_markdown("EMPTY")
    tr.register("ENG", "service", "svc", created_by="op")
    assert len(tr.list_items("ENG", status="pending")) == 1
    assert len(tr.list_items("ENG", status="reclaimed")) == 0


def test_secret_hint():
    assert identifier_looks_like_secret("admin:Password123")
    assert not identifier_looks_like_secret("svc-account-01")
