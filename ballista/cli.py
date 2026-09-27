"""Ballista CLI — 오케스트레이션 엔트리포인트.

    ballista scope verify  <scope.yaml> <keydir>
    ballista run           <scope.yaml> <keydir> <actions.json>
    ballista report        <engagement_id> [--db evidence.db]
    ballista verify-chain  <engagement_id> [--db evidence.db]
    ballista ingest        <scope.yaml> <keydir> <tool> <file> --operator <이름>
    ballista dashboard     <scope.yaml> <keydir> [--out ...] [--detected ...]
    ballista approvals     [--engagement ID] [--db evidence.db]
    ballista approve       <request_id> --approver <이름> [--deny] [--db evidence.db]

run은 actions.json의 각 액션을 Policy Engine에 통과시킨 뒤,
allow면 어댑터를 실행하고 결과를 evidence 체인에 기록한다.
정찰(nmap/nuclei)은 실제 실행되고, 공격 계열은 run() 미구현이라 자연히 멈춘다.
"""

from __future__ import annotations

import argparse
import asyncio
import glob
import json
import os
import sys

from .authorization.scope import load_verified_scope, ScopeError
from .policy.action import Action
from .policy.engine import PolicyEngine, Decision
from .policy.approval import ApprovalStore, require_approval_or_raise
from .adapters.registry import build_registry
from .evidence.store import EvidenceStore, tool_result_to_record
from .reporter.reporter import coverage_summary, navigator_layer
from .dashboard.binding import export_dashboard_json
from .ingest.ingest import ingest_file
from .attack.refs import AttackRef


def _load_keys(keydir: str) -> dict[str, bytes]:
    keys = {}
    for path in glob.glob(os.path.join(keydir, "*.pub")):
        key_id = os.path.splitext(os.path.basename(path))[0]
        with open(path, "rb") as f:
            keys[key_id] = f.read()
    return keys


def _scope(args):
    return load_verified_scope(args.scope, _load_keys(args.keydir))


async def _run(args):
    scope = _scope(args)
    registry = build_registry(scope)
    policy = PolicyEngine()
    store = EvidenceStore(args.db)
    approvals = ApprovalStore(args.db)

    with open(args.actions, "r", encoding="utf-8") as f:
        raw_actions = json.load(f)

    for i, ra in enumerate(raw_actions):
        a = Action(
            action_id=ra.get("action_id", f"act-{i+1:04d}"),
            attack=AttackRef(**ra["attack"]),
            tool_name=ra["tool_name"],
            target=ra["target"],
            params=ra.get("params", {}),
            action_class=ra.get("action_class", "read"),
            rationale=ra.get("rationale", ""),
        )
        decision, reason = policy.evaluate(a, scope)

        if decision is Decision.REQUIRE_APPROVAL:
            st = approvals.status(scope.engagement_id, a.action_id)
            if st == "approved":
                pass  # 승인됨 → 아래에서 실행 진행
            elif st == "denied":
                print(f"[DENIED] {a.action_id} {a.tool_name} → 승인 거부됨, 건너뜀")
                continue
            else:
                rid = approvals.request(scope.engagement_id, a)
                print(f"[APPROVAL] {a.action_id} {a.tool_name} → 승인 필요 "
                      f"(request_id={rid}). 'ballista approve {rid} --approver 이름' 후 재실행")
                store.append(scope.engagement_id, {
                    "action_id": a.action_id, "tool_name": a.tool_name,
                    "target": a.target, "result": "blocked",
                    "reason": f"pending approval ({rid})", "action_class": a.action_class,
                    "attack": {"tactic": a.attack.tactic, "technique": a.attack.technique,
                               "sub_technique": a.attack.sub_technique,
                               "attack_version": a.attack.attack_version},
                })
                continue
        elif decision is not Decision.ALLOW:
            print(f"[{decision.value.upper()}] {a.action_id} {a.tool_name} → {reason}")
            store.append(scope.engagement_id, {
                "action_id": a.action_id, "tool_name": a.tool_name,
                "target": a.target, "result": "blocked", "reason": reason,
                "action_class": a.action_class,
                "attack": {"tactic": a.attack.tactic, "technique": a.attack.technique,
                           "sub_technique": a.attack.sub_technique,
                           "attack_version": a.attack.attack_version},
            })
            continue

        adapter = registry.get(a.tool_name)
        if adapter is None:
            print(f"[SKIP] unknown tool: {a.tool_name}")
            continue
        # 승인 가드: destructive는 승인 없이는 run() 호출 자체를 막는다
        if a.action_class == "destructive" and scope.destructive_requires == "human":
            try:
                require_approval_or_raise(approvals, scope.engagement_id, a)
            except PermissionError as e:
                print(f"[BLOCKED] {a.action_id} → {e}")
                continue
        try:
            result = await adapter.run(adapter.validate(a.params))
            status = "success" if result.returncode == 0 else "failure"
            store.append(scope.engagement_id, tool_result_to_record(
                result, action_id=a.action_id, engagement_id=scope.engagement_id,
                target=a.target, action_class=a.action_class, result_status=status))
            print(f"[{status.upper()}] {a.action_id} {a.tool_name} → {a.target}")
        except NotImplementedError as e:
            print(f"[PENDING] {a.action_id} {a.tool_name} → 실행부 미구현: {e}")
        except FileNotFoundError:
            print(f"[ERROR] {a.action_id} {a.tool_name} → 도구 미설치")
        except Exception as e:
            print(f"[ERROR] {a.action_id} {a.tool_name} → {type(e).__name__}: {e}")


def _report(args):
    store = EvidenceStore(args.db)
    summary = coverage_summary(store, args.engagement_id)
    print(json.dumps(navigator_layer(summary), ensure_ascii=False, indent=2))


def _verify_chain(args):
    store = EvidenceStore(args.db)
    ok = store.verify_chain(args.engagement_id)
    print("체인 무결: OK" if ok else "체인 무결성 위반 감지!")
    sys.exit(0 if ok else 1)


def _dashboard(args):
    scope = _scope(args)
    store = EvidenceStore(args.db)
    detected = set(t.strip() for t in args.detected.split(",") if t.strip()) if args.detected else set()
    path = export_dashboard_json(store, scope, scope.engagement_id, args.out, detected)
    print(f"대시보드 JSON 생성: {path}  (탐지 대조 기법 {len(detected)}개)")


def _ingest(args):
    scope = _scope(args)
    store = EvidenceStore(args.db)
    summary = ingest_file(store, scope, args.tool, args.file, args.operator)
    print(f"수집 완료: {args.tool}  레코드 {summary['records']}건 "
          f"(기록 {summary['ingested']} · 스코프밖 거부 {summary['rejected']})")
    print(f"  원본 해시: {summary['raw_sha256'][:32]}…  운용자: {summary['operator']}")


def _approvals(args):
    pend = ApprovalStore(args.db).list_pending(args.engagement)
    if not pend:
        print("대기 중 승인 없음"); return
    print(f"대기 중 승인 {len(pend)}건:")
    for p in pend:
        print(f"  {p['request_id']}  {p['action_id']}  {p['summary']}")


def _approve(args):
    ap = ApprovalStore(args.db)
    res = ap.decide(args.request_id, args.approver, approved=not args.deny)
    if res is None:
        print(f"해당 request_id 없음: {args.request_id}"); sys.exit(1)
    # 승인/거부 사실을 evidence 체인에 감사 기록으로 남김
    EvidenceStore(args.db).append(res["engagement_id"], {
        "action_id": res["action_id"], "tool_name": "approval",
        "result": res["status"], "action_class": "",
        "reason": f"{res['status']} by {args.approver}",
        "summary": res["summary"],
    })
    print(f"{res['status'].upper()}: {args.request_id} ({res['action_id']}) by {args.approver} — 감사 기록됨")


def main(argv=None):
    p = argparse.ArgumentParser(prog="ballista")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scope").add_subparsers(dest="scmd", required=True)
    spv = sp.add_parser("verify"); spv.add_argument("scope"); spv.add_argument("keydir")

    rp = sub.add_parser("run")
    rp.add_argument("scope"); rp.add_argument("keydir"); rp.add_argument("actions")
    rp.add_argument("--db", default="evidence.db")

    rep = sub.add_parser("report")
    rep.add_argument("engagement_id"); rep.add_argument("--db", default="evidence.db")

    vc = sub.add_parser("verify-chain")
    vc.add_argument("engagement_id"); vc.add_argument("--db", default="evidence.db")

    db = sub.add_parser("dashboard")
    db.add_argument("scope"); db.add_argument("keydir")
    db.add_argument("--db", default="evidence.db")
    db.add_argument("--out", default="docs/dashboard.json")
    db.add_argument("--detected", default="", help="SOC 탐지 technique id 콤마구분 (예: T1046,T1595.002)")

    ing = sub.add_parser("ingest")
    ing.add_argument("scope"); ing.add_argument("keydir")
    ing.add_argument("tool", help="도구 이름 (nmap | nuclei)")
    ing.add_argument("file", help="도구 원본 출력 파일 (nmap XML, nuclei JSONL)")
    ing.add_argument("--operator", required=True, help="수집 운용자 이름")
    ing.add_argument("--db", default="evidence.db")

    apl = sub.add_parser("approvals")
    apl.add_argument("--engagement", default=None); apl.add_argument("--db", default="evidence.db")

    apr = sub.add_parser("approve")
    apr.add_argument("request_id")
    apr.add_argument("--approver", required=True)
    apr.add_argument("--deny", action="store_true", help="승인 대신 거부")
    apr.add_argument("--db", default="evidence.db")

    args = p.parse_args(argv)
    try:
        if args.cmd == "scope":
            _scope(args); print("스코프 서명 검증 통과 · 시간창 유효")
        elif args.cmd == "run":
            asyncio.run(_run(args))
        elif args.cmd == "report":
            _report(args)
        elif args.cmd == "verify-chain":
            _verify_chain(args)
        elif args.cmd == "dashboard":
            _dashboard(args)
        elif args.cmd == "ingest":
            _ingest(args)
        elif args.cmd == "approvals":
            _approvals(args)
        elif args.cmd == "approve":
            _approve(args)
    except ScopeError as e:
        print(f"[SCOPE ERROR] {e}"); sys.exit(2)


if __name__ == "__main__":
    main()
