"""Replay 번들 — 성공 경로를 결정론적 재실행 명세로 export.

docs/handoff.md 5.4의 스펙을 따른다. 이것은 '무엇을 어떤 순서로 재현할지'를
기술한 **명세(데이터)**일 뿐, 스스로 아무것도 실행하지 않는다(공격 실행 없음).
재실행은 사람이 스코프 검증·승인 게이트를 다시 통과시킨 뒤 수행한다.

보안:
- 자격증명 값은 절대 담지 않는다. cred_ref 같은 '참조'만 통과시키고, 값으로 보이는
  키(password/secret/token/...)는 파라미터에서 제거한다(evidence에도 원래 없음).
- 성공(result == success)한, 실제 도구 실행 레코드만 스텝으로 포함한다.
  통제/감사 레코드(authorization·approval·blocked)는 제외한다.
"""

from __future__ import annotations

from datetime import datetime, timezone

import yaml

REPLAY_VERSION = "1.0"

# 파라미터에서 값 유출을 막기 위해 제거하는 키(참조 cred_ref는 유지).
_SECRET_KEY_HINTS = ("password", "passwd", "secret", "token", "private_key",
                     "privkey", "credential_value", "hash", "ntlm")

# 통제/감사 성격의 tool_name(재실행 스텝이 아님).
_NON_STEP_TOOLS = {"authorization", "approval"}


def _redact_params(params: dict) -> dict:
    """값으로 보이는 키를 제거. cred_ref 등 '참조'는 유지."""
    out = {}
    for k, v in (params or {}).items():
        lk = str(k).lower()
        if any(h in lk for h in _SECRET_KEY_HINTS) and not lk.endswith("_ref"):
            continue
        out[k] = v
    return out


def _step_params(rec: dict) -> dict:
    """재실행에 필요한 파라미터를 레코드에서 뽑는다.
    우선순위: 원본 params > (없으면) argv에서 재구성 힌트."""
    if rec.get("params"):
        return _redact_params(rec["params"])
    # 원본 params가 없는 (구버전/ingest) 레코드: 대상만이라도 명세에 남긴다.
    p: dict = {}
    if rec.get("target"):
        p["target"] = rec["target"]
    if rec.get("argv"):
        p["argv"] = rec["argv"]     # 사람 참고용(그대로 실행 보장은 아님)
    return p


def build_replay_bundle(store, engagement_id: str) -> dict:
    """evidence 체인 → replay 번들(dict). 성공한 실행 스텝만, 기록 순서대로."""
    steps = []
    order = 0
    for rec in store.records(engagement_id):
        if rec.get("result") != "success":
            continue
        tool = rec.get("tool_name")
        if not tool or tool in _NON_STEP_TOOLS:
            continue
        attack = rec.get("attack") or {}
        if not attack.get("technique"):
            continue
        order += 1
        steps.append({
            "order": order,
            "attack": {
                "technique": attack.get("sub_technique") or attack.get("technique"),
                "version": attack.get("attack_version", "15"),
            },
            "tool": tool,
            "params": _step_params(rec),
        })
    return {
        "replay_version": REPLAY_VERSION,
        "engagement_id": engagement_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "steps": steps,
    }


def export_replay_yaml(store, engagement_id: str, out_path: str) -> dict:
    """replay 번들을 YAML 파일로 저장. 반환: {path, steps}."""
    bundle = build_replay_bundle(store, engagement_id)
    with open(out_path, "w", encoding="utf-8") as f:
        # steps 안 dict 순서를 유지하려면 sort_keys=False
        yaml.safe_dump(bundle, f, allow_unicode=True, sort_keys=False)
    return {"path": out_path, "steps": len(bundle["steps"])}
