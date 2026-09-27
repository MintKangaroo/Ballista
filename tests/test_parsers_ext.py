"""확장 수집 파서 테스트 — masscan XML · httpx JSONL · gobuster (읽기 전용)."""

from __future__ import annotations

from ballista.ingest.parsers import (
    parse_masscan_xml, parse_httpx_jsonl, parse_gobuster, PARSERS,
)
from ballista.ingest.ingest import ingest_file
from ballista.evidence.store import EvidenceStore


def test_registered():
    for name in ("masscan", "httpx", "gobuster"):
        assert name in PARSERS


def test_masscan_xml():
    raw = b"""<?xml version="1.0"?>
    <nmaprun scanner="masscan">
      <host><address addr="10.0.0.5" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="443">
          <state state="open"/><service name="https"/></port></ports>
      </host>
      <host><address addr="10.0.0.6" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="22">
          <state state="closed"/></port></ports>
      </host>
    </nmaprun>"""
    recs = parse_masscan_xml(raw)
    # 열린 포트가 있는 호스트만
    assert len(recs) == 1
    r = recs[0]
    assert r["target"] == "10.0.0.5"
    assert r["tool_name"] == "masscan"
    assert r["attack"]["technique"] == "T1046"
    assert r["parsed"]["open_ports"][0]["port"] == 443


def test_httpx_jsonl():
    raw = (b'{"host":"10.0.0.5","url":"http://10.0.0.5","status_code":200,'
           b'"title":"Home","webserver":"nginx","tech":["Nginx"]}\n'
           b'garbage line\n'
           b'{"host":"10.0.0.5","url":"http://10.0.0.5:8080","status_code":403}\n')
    recs = parse_httpx_jsonl(raw)
    assert len(recs) == 1                      # 같은 호스트로 집계
    r = recs[0]
    assert r["target"] == "10.0.0.5"
    assert len(r["parsed"]["probes"]) == 2
    assert r["attack"]["technique"] == "T1595"


def test_gobuster_text_needs_target_fallback(tmp_path):
    raw = (b"/admin                (Status: 301) [Size: 169]\n"
           b"/images               (Status: 200) [Size: 1234]\n"
           b"garbage\n")
    recs = parse_gobuster(raw)
    assert len(recs) == 1
    assert recs[0]["target"] is None          # 텍스트엔 호스트 없음
    paths = recs[0]["parsed"]["paths"]
    assert {p["path"] for p in paths} == {"/admin", "/images"}
    assert paths[0]["status"] == 301


def test_gobuster_json_has_host():
    raw = (b'[{"url":"http://10.0.0.5/admin","path":"/admin","status":301,"size":169}]')
    recs = parse_gobuster(raw)
    assert recs[0]["target"] == "10.0.0.5"


class _Scope:
    engagement_id = "ENG-ING-0001"
    def is_target_in_scope(self, t):
        return t == "10.0.0.5"


def test_ingest_gobuster_with_target_fallback(tmp_path):
    """gobuster 텍스트 + --target 폴백으로 스코프 판정·기록되는지."""
    f = tmp_path / "gob.txt"
    f.write_bytes(b"/admin (Status: 301) [Size: 169]\n")
    store = EvidenceStore(str(tmp_path / "e.db"))
    scope = _Scope()

    # 폴백 없으면 target="" → 스코프 밖으로 거부
    s1 = ingest_file(store, scope, "gobuster", str(f), "op")
    assert s1["rejected"] == 1 and s1["ingested"] == 0

    # 폴백 주면 스코프 안으로 기록
    s2 = ingest_file(store, scope, "gobuster", str(f), "op", default_target="10.0.0.5")
    assert s2["ingested"] == 1 and s2["rejected"] == 0
    assert store.verify_chain("ENG-ING-0001")
