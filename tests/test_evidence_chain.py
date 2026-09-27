"""증거 해시 체인 무결성 증명."""
import os, tempfile
from ballista.evidence.store import EvidenceStore


def test_chain_detects_tampering():
    fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    try:
        store = EvidenceStore(path)
        for i in range(3):
            store.append("ENG-TEST", {"action_id": f"a{i}", "result": "success"})
        assert store.verify_chain("ENG-TEST") is True

        # 저장소 내부 레코드를 직접 위조
        store._db.execute(
            "UPDATE evidence SET record_json=? WHERE seq=("
            "SELECT MIN(seq) FROM evidence WHERE engagement_id='ENG-TEST')",
            ('{"action_id":"tampered","result":"success"}',))
        store._db.commit()
        assert store.verify_chain("ENG-TEST") is False
    finally:
        os.remove(path)
