"""공격 경로 그래프 데이터 테스트 — 노드(호스트/자격증명/진입점)·엣지(기법)."""

from __future__ import annotations

from ballista.dashboard.binding import build_attack_path_graph


def test_graph_nodes_and_edges():
    records = [
        # 성공 정찰 → entry에서 host로 T1046 엣지
        {"result": "success", "target": "10.0.0.5", "tool_name": "nmap",
         "attack": {"technique": "T1046"}, "params": {"targets": ["10.0.0.5"]}},
        # 실패/차단은 그래프에 안 들어감
        {"result": "blocked", "target": "8.8.8.8",
         "attack": {"technique": "T1046"}},
        # 측면이동: 10.0.0.5 → app01, 자격증명 cred-007 참조
        {"result": "success", "target": "app01", "tool_name": "netexec.smb",
         "attack": {"technique": "T1021", "sub_technique": "T1021.002"},
         "params": {"source": "10.0.0.5", "cred_ref": "cred-007"}},
    ]
    g = build_attack_path_graph(records)
    node_ids = {n["id"] for n in g["nodes"]}
    assert "entry" in node_ids
    assert "10.0.0.5" in node_ids and "app01" in node_ids
    assert "cred-007" in node_ids
    kinds = {n["id"]: n["kind"] for n in g["nodes"]}
    assert kinds["cred-007"] == "credential"
    assert kinds["10.0.0.5"] == "host"

    # 엣지: 성공 2건만
    assert len(g["edges"]) == 2
    recon = next(e for e in g["edges"] if e["to"] == "10.0.0.5")
    assert recon["from"] == "entry" and recon["technique"] == "T1046"
    lateral = next(e for e in g["edges"] if e["to"] == "app01")
    assert lateral["from"] == "10.0.0.5"
    assert lateral["technique"] == "T1021.002"       # 하위기법 우선


def test_empty_graph_has_entry_only():
    g = build_attack_path_graph([])
    assert g["nodes"] == [{"id": "entry", "kind": "entry", "label": "진입점"}]
    assert g["edges"] == []
