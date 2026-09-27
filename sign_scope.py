"""개발용: Ed25519 키페어를 만들고 scope.example.yaml에 서명을 채운다.
    python sign_scope.py scope.example.yaml keys/
공개키는 keys/<key_id>.pub 로 저장(신뢰 키스토어). 개인키는 keys/<key_id>.key.
운영에서는 개인키를 코드베이스/실행환경 밖에서 관리할 것.
"""
import sys, os, yaml, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)
from ballista.authorization.scope import canonical_bytes

scope_path, keydir = sys.argv[1], sys.argv[2]
os.makedirs(keydir, exist_ok=True)
doc = yaml.safe_load(open(scope_path, encoding="utf-8"))
key_id = doc["signature"]["key_id"]

priv = Ed25519PrivateKey.generate()
# cryptography 3.4.x 호환: private_bytes_raw/public_bytes_raw 대신 Raw 인코딩 사용
raw_priv = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
open(os.path.join(keydir, key_id + ".key"), "wb").write(raw_priv)
open(os.path.join(keydir, key_id + ".pub"), "wb").write(raw_pub)

sig = priv.sign(canonical_bytes(doc))
doc["signature"]["value"] = sig.hex()
yaml.safe_dump(doc, open(scope_path, "w", encoding="utf-8"), allow_unicode=True, sort_keys=False)
print(f"서명 완료 · 공개키: {keydir}/{key_id}.pub")
