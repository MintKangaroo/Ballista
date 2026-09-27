"""수집 어댑터/파서 증명."""
import os, tempfile
from datetime import datetime, timezone, timedelta
from ballista.ingest.parsers import parse_nmap_xml, parse_nuclei_jsonl
from ballista.ingest.ingest import ingest_file
from ballista.evidence.store import EvidenceStore
from ballista.authorization.scope import EngagementScope

NMAP_XML = b'''<?xml version="1.0"?><nmaprun start="1759300000">
<host><address addr="10.20.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host>
</nmaprun>'''

NUCLEI_JSONL = (b'{"template-id":"weak-tls","host":"https://app01.internal:8443/",'
                b'"matched-at":"app01.internal:8443","info":{"name":"TLS \xea\xb5\xac\xec\x84\xb1 \xec\xb7\xa8\xec\x95\xbd","severity":"medium"}}\n')


def test_parse_nmap():
    recs = parse_nmap_xml(NMAP_XML)
    assert len(recs) == 1
    assert recs[0]["target"] == "10.20.0.5"
    assert recs[0]["attack"]["technique"] == "T1046"
    assert len(recs[0]["parsed"]["open_ports"]) == 2


def test_parse_nuclei():
    recs = parse_nuclei_jsonl(NUCLEI_JSONL)
    assert len(recs) == 1
    assert recs[0]["attack"]["sub_technique"] == "T1595.002"
    assert recs[0]["parsed"]["findings"][0]["severity"] == "medium"


def _scope():
    now = datetime.now(timezone.utc)
    return EngagementScope(
        raw={}, engagement_id="ENG-T", in_scope_cidrs=["10.20.0.0/24"],
        in_scope_hosts=["app01.internal"], out_of_scope_hosts=[],
        time_start=now - timedelta(days=1), time_end=now + timedelta(days=1),
        max_action_class="modify")


def test_ingest_records_and_scope_check():
    fd, dbp = tempfile.mkstemp(suffix=".db"); os.close(fd)
    fd, xmlp = tempfile.mkstemp(suffix=".xml"); os.close(fd)
    open(xmlp, "wb").write(NMAP_XML)
    try:
        store = EvidenceStore(dbp)
        scope = _scope()
        summ = ingest_file(store, scope, "nmap", xmlp, operator="윤지창")
        assert summ["ingested"] == 1 and summ["rejected"] == 0
        recs = list(store.records("ENG-T"))
        assert recs[0]["operator"] == "윤지창"
        assert "raw_output_sha256" in recs[0]
        assert store.verify_chain("ENG-T") is True
    finally:
        os.remove(dbp); os.remove(xmlp)


def test_ingest_rejects_out_of_scope():
    fd, dbp = tempfile.mkstemp(suffix=".db"); os.close(fd)
    fd, xmlp = tempfile.mkstemp(suffix=".xml"); os.close(fd)
    # 범위 밖 대상
    open(xmlp, "wb").write(NMAP_XML.replace(b"10.20.0.5", b"8.8.8.8"))
    try:
        store = EvidenceStore(dbp)
        summ = ingest_file(store, _scope(), "nmap", xmlp, operator="윤지창")
        assert summ["rejected"] == 1 and summ["ingested"] == 0
    finally:
        os.remove(dbp); os.remove(xmlp)
