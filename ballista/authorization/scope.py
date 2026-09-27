"""Engagement Scope — 서명된 교전 범위.

INV-3: 서명 검증을 통과한 스코프 없이는 아무것도 실행되지 않는다.
서명 대상은 signature.value를 제외한 문서를 정규화(JCS 근사: sort_keys)한 바이트.
공개키만 신뢰 키스토어로 보유하고, 개인키는 코드베이스에 두지 않는다.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import yaml

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    Ed25519PublicKey = None
    InvalidSignature = Exception

_CLASS_RANK = {"read": 0, "modify": 1, "destructive": 2}


def canonical_bytes(doc: dict) -> bytes:
    """서명 대상 정규화. signature.value만 제외하고 결정론적 직렬화.
    (완전한 RFC 8785을 원하면 jcs 패키지로 교체 가능)"""
    d = json.loads(json.dumps(doc))          # 깊은 복사
    sig = d.get("signature", {})
    sig.pop("value", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class ScopeError(Exception):
    pass


@dataclass
class EngagementScope:
    raw: dict
    engagement_id: str
    in_scope_cidrs: list[str]
    in_scope_hosts: list[str]
    out_of_scope_hosts: list[str]
    time_start: datetime
    time_end: datetime
    max_action_class: str
    allowed_techniques: list[str] = field(default_factory=list)
    denied_techniques: list[str] = field(default_factory=list)
    destructive_requires: str = "human"

    # ---- 판정 ----
    def is_target_in_scope(self, target: str) -> bool:
        host = self._host_of(target)
        if host in self.out_of_scope_hosts:      # 금지 최우선
            return False
        if host in self.in_scope_hosts:
            return True
        try:
            ip = ipaddress.ip_address(host)
            for cidr in self.in_scope_cidrs:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass
        return False                              # deny-by-default

    def is_within_time_window(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.time_start <= now <= self.time_end

    def is_technique_allowed(self, tid: str) -> bool:
        if tid in self.denied_techniques:         # 금지 최우선
            return False
        if self.allowed_techniques:               # 화이트리스트가 있으면 그 안에서만
            return tid in self.allowed_techniques
        return True

    def class_within_max(self, action_class: str) -> bool:
        return _CLASS_RANK[action_class] <= _CLASS_RANK[self.max_action_class]

    @staticmethod
    def _host_of(target: str) -> str:
        t = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        return t


def load_verified_scope(yaml_path: str, trusted_keys: dict[str, bytes]) -> EngagementScope:
    """YAML을 읽어 서명을 검증하고 EngagementScope를 반환.
    trusted_keys: {key_id: raw_public_key_bytes}
    """
    with open(yaml_path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f)

    if doc.get("schema_version") != "1.0":
        raise ScopeError("unsupported schema_version")

    sig = doc.get("signature") or {}
    key_id = sig.get("key_id")
    value_hex = sig.get("value")
    if not key_id or not value_hex:
        raise ScopeError("missing signature")
    if key_id not in trusted_keys:
        raise ScopeError(f"unknown key_id: {key_id}")
    if Ed25519PublicKey is None:
        raise ScopeError("cryptography 미설치 — 서명 검증 불가")

    pub = Ed25519PublicKey.from_public_bytes(trusted_keys[key_id])
    try:
        pub.verify(bytes.fromhex(value_hex), canonical_bytes(doc))
    except InvalidSignature:
        raise ScopeError("signature verification failed")

    t = doc["target"]
    c = doc["constraints"]
    tw = c["time_window"]
    scope = EngagementScope(
        raw=doc,
        engagement_id=doc["engagement"]["id"],
        in_scope_cidrs=t.get("in_scope_cidrs", []),
        in_scope_hosts=t.get("in_scope_hosts", []),
        out_of_scope_hosts=t.get("out_of_scope_hosts", []),
        time_start=_dt(tw["start"]),
        time_end=_dt(tw["end"]),
        max_action_class=c.get("max_action_class", "read"),
        allowed_techniques=c.get("allowed_techniques", []),
        denied_techniques=c.get("denied_techniques", []),
        destructive_requires=(doc.get("approval") or {}).get("destructive_requires", "human"),
    )
    if not scope.is_within_time_window():
        raise ScopeError("outside engagement time window")
    return scope


def _dt(s: str) -> datetime:
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
