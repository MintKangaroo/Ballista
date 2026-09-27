"""Replay 번들 테스트 — 성공 스텝만, 순서 보존, 자격증명 값 미포함."""

from __future__ import annotations

import yaml

from ballista.evidence.store import EvidenceStore
from ballista.reporter.replay import build_replay_bundle, export_replay_yaml


def _seed(store, eng):
    # 1) 성공 정찰 (params 포함)
    store.append(eng, {
        "action_id": "a1", "tool_name": "nmap", "target": "10.0.0.5",
        "result": "success", "action_class": "read",
        "attack": {"tactic": "TA0007", "technique": "T1046",
                   "sub_technique": None, "attack_version": "15"},
        "params": {"targets": ["10.0.0.5"], "top_ports": 100},
    })
    # 2) 범위 밖 차단 (제외되어야)
    store.append(eng, {
        "action_id": "a2", "tool_name": "nmap", "target": "8.8.8.8",
        "result": "blocked", "reason": "out of scope",
        "attack": {"tactic": "TA0007", "technique": "T1046"},
    })
    # 3) 승인 감사 레코드 (제외되어야)
    store.append(eng, {
        "action_id": "a1", "tool_name": "approval", "result": "approved",
        "action_class": "", "reason": "approved by 보안팀장",
    })
    # 4) 성공 측면이동 — 자격증명은 '참조'만, 값(password)은 제거되어야
    store.append(eng, {
        "action_id": "a4", "tool_name": "netexec.smb", "target": "app01",
        "result": "success", "action_class": "modify",
        "attack": {"tactic": "TA0008", "technique": "T1021",
                   "sub_technique": "T1021.002", "attack_version": "15"},
        "params": {"target": "app01", "cred_ref": "cred-007", "password": "SHOULD_NOT_APPEAR"},
    })


def test_bundle_selects_success_steps_in_order(tmp_path):
    store = EvidenceStore(str(tmp_path / "e.db"))
    _seed(store, "ENG-R-1")
    b = build_replay_bundle(store, "ENG-R-1")

    assert b["replay_version"] == "1.0"
    assert b["engagement_id"] == "ENG-R-1"
    # blocked·approval 제외 → 성공 실행 2건만
    assert len(b["steps"]) == 2
    assert [s["order"] for s in b["steps"]] == [1, 2]
    assert b["steps"][0]["tool"] == "nmap"
    assert b["steps"][0]["attack"]["technique"] == "T1046"
    # 하위기법 우선
    assert b["steps"][1]["attack"]["technique"] == "T1021.002"


def test_no_credential_values(tmp_path):
    store = EvidenceStore(str(tmp_path / "e.db"))
    _seed(store, "ENG-R-2")
    b = build_replay_bundle(store, "ENG-R-2")
    lateral = b["steps"][1]
    assert lateral["params"]["cred_ref"] == "cred-007"     # 참조는 유지
    assert "password" not in lateral["params"]             # 값은 제거
    assert "SHOULD_NOT_APPEAR" not in yaml.safe_dump(b)


def test_export_yaml_roundtrip(tmp_path):
    store = EvidenceStore(str(tmp_path / "e.db"))
    _seed(store, "ENG-R-3")
    out = str(tmp_path / "replay.yaml")
    res = export_replay_yaml(store, "ENG-R-3", out)
    assert res["steps"] == 2
    loaded = yaml.safe_load(open(out, encoding="utf-8"))
    assert loaded["steps"][0]["order"] == 1
    assert loaded["engagement_id"] == "ENG-R-3"
