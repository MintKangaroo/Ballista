"""리포트 생성기 테스트 — evidence → Markdown 초안이 정확히 조립되는지 검증."""

from __future__ import annotations

from ballista.evidence.store import EvidenceStore
from ballista.reporter.report_builder import build_markdown_report, write_report


class _FakeScope:
    """binding/report가 읽는 최소 스코프 인터페이스."""
    engagement_id = "ENG-TEST-0001"
    in_scope_cidrs = ["10.0.0.0/24"]
    in_scope_hosts = ["app01"]
    out_of_scope_hosts = ["8.8.8.8"]
    max_action_class = "modify"
    raw = {"engagement": {"id": "ENG-TEST-0001", "name": "테스트 교전",
                          "authorized_by": "보안팀장", "roe_document_ref": "RoE-T"}}

    def is_within_time_window(self, now=None):
        return True


def _seed(store: EvidenceStore, eng: str):
    # 성공 정찰(T1046) + 범위 밖 차단 + nuclei findings 1건
    store.append(eng, {
        "action_id": "a1", "tool_name": "nmap", "target": "10.0.0.5",
        "result": "success", "action_class": "read",
        "attack": {"tactic": "TA0007", "technique": "T1046",
                   "sub_technique": None, "attack_version": "15"},
        "finished_at": "2026-09-27T01:00:00+00:00",
    })
    store.append(eng, {
        "action_id": "a2", "tool_name": "nmap", "target": "8.8.8.8",
        "result": "blocked", "reason": "target out of scope: 8.8.8.8",
        "action_class": "read",
        "attack": {"tactic": "TA0007", "technique": "T1046",
                   "sub_technique": None, "attack_version": "15"},
    })
    store.append(eng, {
        "action_id": "a3", "tool_name": "nuclei", "target": "10.0.0.5",
        "result": "success", "action_class": "read",
        "attack": {"tactic": "TA0043", "technique": "T1595",
                   "sub_technique": "T1595.002", "attack_version": "15"},
        "parsed": {"findings": [{"name": "노출된 관리 페이지", "template_id": "expo-admin",
                                 "severity": "high", "host": "10.0.0.5"}]},
        "finished_at": "2026-09-27T01:05:00+00:00",
    })


def test_report_sections_and_counts(tmp_path):
    db = str(tmp_path / "e.db")
    store = EvidenceStore(db)
    scope = _FakeScope()
    _seed(store, scope.engagement_id)

    # T1046은 탐지됨으로 간주 → 탐지 공백은 T1595.002만 남아야 함
    md = build_markdown_report(store, scope, scope.engagement_id,
                               detected_technique_ids={"T1046"}, with_prompts=True)

    # 필수 섹션
    for h in ["# 침투 테스트 리포트", "## 1. 경영 요약", "## 2. 스코프",
              "## 3. ATT&CK", "## 4. 실행 액션 타임라인", "## 5. 발견 취약점",
              "## 6. 탐지 공백", "## 7. 증거 무결성", "## 부록 A."]:
        assert h in md, f"섹션 누락: {h}"

    # 메타 반영
    assert "테스트 교전" in md
    assert "보안팀장" in md
    assert "✅ OK" in md            # 체인 무결

    # 실행 액션 수·취약점·타임라인
    assert "실행된 액션**: 3건" in md
    assert "노출된 관리 페이지" in md
    assert "10.0.0.5" in md

    # 탐지 공백: 탐지된 T1046은 빠지고 미탐지 성공 기법 T1595.002만 남음
    assert "T1595.002" in md
    assert "탐지 공백**: 1건" in md

    # 부록에 어시스턴트 프롬프트(방어 역할 고정 문구) 포함
    assert "방어 분석 어시스턴트" in md


def test_report_no_gaps_when_all_detected(tmp_path):
    db = str(tmp_path / "e2.db")
    store = EvidenceStore(db)
    scope = _FakeScope()
    _seed(store, scope.engagement_id)

    md = build_markdown_report(store, scope, scope.engagement_id,
                               detected_technique_ids={"T1046", "T1595.002"})
    assert "탐지 공백 없음" in md


def test_write_report_creates_md_without_pandoc_pdf(tmp_path):
    db = str(tmp_path / "e3.db")
    store = EvidenceStore(db)
    scope = _FakeScope()
    _seed(store, scope.engagement_id)

    out = str(tmp_path / "report.md")
    res = write_report(store, scope, scope.engagement_id, out, pdf=False)
    assert res["md"] == out
    assert (tmp_path / "report.md").exists()
    assert res["pdf"] is None
