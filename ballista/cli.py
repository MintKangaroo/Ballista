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
from .policy.notify import console_notifier, webhook_notifier
from .adapters.registry import build_registry
from .evidence.store import EvidenceStore, tool_result_to_record
from .reporter.reporter import coverage_summary, navigator_layer
from .reporter.report_builder import write_report
from .reporter.replay import export_replay_yaml
from .ingest.ingest import ingest_file
from .attack.refs import AttackRef
from .dashboard.binding import export_dashboard_json, build_dashboard_data
from .reporter.reporter import detection_gaps
from .assistant.assistant import build_summary_prompt, build_gap_prompt, build_learn_prompt
from .assistant.client import ask_claude, sdk_available, DEFAULT_MODEL
from .cleanup.tracker import CleanupTracker, identifier_looks_like_secret


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
    notifier = webhook_notifier(args.notify_webhook) if getattr(args, "notify_webhook", None) else console_notifier
    approvals = ApprovalStore(args.db, notifier=notifier)
    # 스코프의 승인 설정(정족수·TTL). 없으면 기본 1-of-1, 무기한.
    appr_cfg = (getattr(scope, "raw", {}) or {}).get("approval") or {}
    quorum = int(appr_cfg.get("quorum", 1))
    ttl_seconds = appr_cfg.get("ttl_seconds")

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
            elif st == "expired":
                print(f"[EXPIRED] {a.action_id} {a.tool_name} → 승인 요청 만료됨, 건너뜀")
                continue
            else:
                rid = approvals.request(scope.engagement_id, a,
                                        ttl_seconds=ttl_seconds, quorum=quorum)
                extra = f" · 정족수 {quorum}" + (f" · TTL {ttl_seconds}s" if ttl_seconds else "")
                print(f"[APPROVAL] {a.action_id} {a.tool_name} → 승인 필요 "
                      f"(request_id={rid}{extra}). 'ballista approve {rid} --approver 이름' 후 재실행")
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
            validated = adapter.validate(a.params)
            simulated = bool(getattr(args, "simulate", False)
                             and getattr(adapter, "supports_simulation", False))
            if simulated:
                result = adapter.simulate(validated)     # 실제 실행 없음(합성 결과)
            else:
                result = await adapter.run(validated)
            status = "success" if result.returncode == 0 else "failure"
            rec = tool_result_to_record(
                result, action_id=a.action_id, engagement_id=scope.engagement_id,
                target=a.target, action_class=a.action_class, result_status=status)
            rec["params"] = a.params        # 결정론적 replay 번들 재구성용(원본 파라미터)
            if simulated:
                rec["simulated"] = True     # evidence에 '합성'으로 낙인
            store.append(scope.engagement_id, rec)
            tag = " (SIMULATED)" if simulated else ""
            print(f"[{status.upper()}] {a.action_id} {a.tool_name} → {a.target}{tag}")
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


def _report_doc(args):
    scope = _scope(args)
    store = EvidenceStore(args.db)
    detected = set(t.strip() for t in args.detected.split(",") if t.strip()) if args.detected else set()
    res = write_report(store, scope, scope.engagement_id, args.out,
                       detected_technique_ids=detected,
                       with_prompts=args.with_prompts, pdf=args.pdf)
    print(f"리포트 생성: {res['md']}")
    if res.get("pdf"):
        print(f"PDF 생성: {res['pdf']}")
    elif res.get("pdf_note"):
        print(f"  ({res['pdf_note']})")


def _cleanup(args):
    tr = CleanupTracker(args.db)
    if args.ccmd == "register":
        scope = _scope(args)
        if identifier_looks_like_secret(args.id):
            print("[경고] 식별자에 비밀값이 섞인 것 같습니다. 식별자만 기록하세요(값 금지).")
        item_id = tr.register(scope.engagement_id, args.type, args.id,
                              created_by=args.by, host=args.host, note=args.note)
        print(f"등록: {item_id}  {args.type}:{args.id} — evidence 감사 기록됨")
    elif args.ccmd == "list":
        items = tr.list_items(args.engagement_id, args.status)
        s = tr.summary(args.engagement_id)
        print(f"총 {s['total']}건 · 미회수 {s['pending']} · 회수완료 {s['reclaimed']}")
        for i in items:
            print(f"  [{i['status']}] {i['item_id']}  {i['artifact_type']}:{i['identifier']}"
                  + (f" @ {i['host']}" if i['host'] else ""))
    elif args.ccmd == "reclaim":
        res = tr.reclaim(args.item_id, args.by)
        if res is None:
            print(f"해당 item_id 없음: {args.item_id}"); sys.exit(1)
        print(f"회수 완료: {args.item_id} ({res['artifact_type']}:{res['identifier']}) "
              f"by {args.by} — evidence 감사 기록됨")
    elif args.ccmd == "checklist":
        md = tr.checklist_markdown(args.engagement_id)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(md)
            print(f"체크리스트 생성: {args.out}")
        else:
            print(md)


def _explain(args):
    scope = _scope(args)
    store = EvidenceStore(args.db)
    detected = set(t.strip() for t in args.detected.split(",") if t.strip()) if args.detected else set()
    data = build_dashboard_data(store, scope, scope.engagement_id, detected)

    if args.mode == "summary":
        prompt = build_summary_prompt(data)
    elif args.mode == "gaps":
        from .reporter.reporter import coverage_summary
        gaps = detection_gaps(coverage_summary(store, scope.engagement_id), detected)
        prompt = build_gap_prompt(gaps)
    else:  # learn
        if not args.question:
            print("[오류] --mode learn 에는 --question 이 필요합니다."); sys.exit(2)
        prompt = build_learn_prompt(args.question)

    if not args.send:
        print("# dry-run — 아래 프롬프트를 LLM에 보내려면 --send 를 붙이세요.\n")
        print(prompt)
        return

    if not sdk_available():
        print("[오류] anthropic SDK 미설치. `pip install anthropic` 후 --send 하세요."); sys.exit(1)
    try:
        answer = ask_claude(prompt, model=args.model)
    except Exception as e:
        print(f"[오류] LLM 호출 실패: {type(e).__name__}: {e}"); sys.exit(1)
    print(answer)


def _replay(args):
    store = EvidenceStore(args.db)
    res = export_replay_yaml(store, args.engagement_id, args.out)
    print(f"replay 번들 생성: {res['path']}  (성공 스텝 {res['steps']}개)")
    print("  ※ 명세일 뿐이며 스스로 실행되지 않습니다. 재실행은 스코프 검증·승인 게이트를 "
          "다시 통과시킨 뒤 운용자가 수행합니다.")


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
    summary = ingest_file(store, scope, args.tool, args.file, args.operator,
                          default_target=args.target)
    print(f"수집 완료: {args.tool}  레코드 {summary['records']}건 "
          f"(기록 {summary['ingested']} · 스코프밖 거부 {summary['rejected']})")
    print(f"  원본 해시: {summary['raw_sha256'][:32]}…  운용자: {summary['operator']}")


def _approvals(args):
    pend = ApprovalStore(args.db).list_pending(args.engagement)
    if not pend:
        print("대기 중 승인 없음"); return
    print(f"대기 중 승인 {len(pend)}건:")
    for p in pend:
        prog = f" [{p.get('approvals', 0)}/{p.get('quorum', 1)}]"
        print(f"  {p['request_id']}  {p['action_id']}  {p['summary']}{prog}")


def _approve(args):
    notifier = webhook_notifier(args.notify_webhook) if args.notify_webhook else console_notifier
    ap = ApprovalStore(args.db, notifier=notifier)
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
    tail = ""
    if res["status"] == "pending":
        tail = f" — 정족수 대기 {res.get('approvals')}/{res.get('quorum')}"
    elif res["status"] == "expired":
        tail = " — 요청이 만료되어 결정 불가"
    print(f"{res['status'].upper()}: {args.request_id} ({res['action_id']}) "
          f"by {args.approver} — 감사 기록됨{tail}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="ballista")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scope").add_subparsers(dest="scmd", required=True)
    spv = sp.add_parser("verify"); spv.add_argument("scope"); spv.add_argument("keydir")

    rp = sub.add_parser("run")
    rp.add_argument("scope"); rp.add_argument("keydir"); rp.add_argument("actions")
    rp.add_argument("--db", default="evidence.db")
    rp.add_argument("--notify-webhook", default=None, help="승인 요청 알림 웹훅 URL")
    rp.add_argument("--simulate", action="store_true",
                    help="공격 계열 어댑터를 실제 실행 대신 합성 결과로 시뮬레이션(테스트/시연용)")

    rep = sub.add_parser("report")
    rep.add_argument("engagement_id"); rep.add_argument("--db", default="evidence.db")

    rd = sub.add_parser("report-doc", help="evidence → 기술/경영 리포트 초안(.md)")
    rd.add_argument("scope"); rd.add_argument("keydir")
    rd.add_argument("--db", default="evidence.db")
    rd.add_argument("--out", default="report.md")
    rd.add_argument("--detected", default="", help="SOC 탐지 technique id 콤마구분")
    rd.add_argument("--with-prompts", action="store_true",
                    help="부록에 방어 어시스턴트 LLM 프롬프트 포함")
    rd.add_argument("--pdf", action="store_true", help="pandoc 있으면 PDF도 생성")

    cl = sub.add_parser("cleanup", help="교전 중 생성 아티팩트 추적·회수 체크리스트")
    clsub = cl.add_subparsers(dest="ccmd", required=True)
    clr = clsub.add_parser("register", help="생성 아티팩트 등록")
    clr.add_argument("scope"); clr.add_argument("keydir")
    clr.add_argument("--type", required=True,
                     help="session|account|file|scheduled_task|service|other")
    clr.add_argument("--id", required=True, help="식별자(값 아님): 계정명·경로·세션ID 등")
    clr.add_argument("--host", default=""); clr.add_argument("--note", default="")
    clr.add_argument("--by", required=True, help="생성 운용자")
    clr.add_argument("--db", default="evidence.db")
    cll = clsub.add_parser("list", help="아티팩트 목록")
    cll.add_argument("engagement_id"); cll.add_argument("--status", default=None,
                     choices=["pending", "reclaimed"])
    cll.add_argument("--db", default="evidence.db")
    clrc = clsub.add_parser("reclaim", help="아티팩트 회수 처리")
    clrc.add_argument("item_id"); clrc.add_argument("--by", required=True)
    clrc.add_argument("--db", default="evidence.db")
    clc = clsub.add_parser("checklist", help="회수 체크리스트(Markdown)")
    clc.add_argument("engagement_id"); clc.add_argument("--out", default=None)
    clc.add_argument("--db", default="evidence.db")

    ex = sub.add_parser("explain", help="방어 어시스턴트로 교전 해석/탐지공백 방어/ATT&CK 학습")
    ex.add_argument("scope"); ex.add_argument("keydir")
    ex.add_argument("--db", default="evidence.db")
    ex.add_argument("--mode", choices=["summary", "gaps", "learn"], default="summary")
    ex.add_argument("--question", default="", help="--mode learn 질문")
    ex.add_argument("--detected", default="", help="SOC 탐지 technique id 콤마구분")
    ex.add_argument("--send", action="store_true", help="실제 LLM 호출(미지정 시 프롬프트만 출력)")
    ex.add_argument("--model", default=DEFAULT_MODEL)

    rpl = sub.add_parser("replay", help="성공 경로를 결정론적 재실행 명세(YAML)로 export")
    rpl.add_argument("engagement_id")
    rpl.add_argument("--db", default="evidence.db")
    rpl.add_argument("--out", default="replay.yaml")

    vc = sub.add_parser("verify-chain")
    vc.add_argument("engagement_id"); vc.add_argument("--db", default="evidence.db")

    db = sub.add_parser("dashboard")
    db.add_argument("scope"); db.add_argument("keydir")
    db.add_argument("--db", default="evidence.db")
    db.add_argument("--out", default="docs/dashboard.json")
    db.add_argument("--detected", default="", help="SOC 탐지 technique id 콤마구분 (예: T1046,T1595.002)")

    ing = sub.add_parser("ingest")
    ing.add_argument("scope"); ing.add_argument("keydir")
    ing.add_argument("tool", help="도구 이름 (nmap | nuclei | masscan | httpx | gobuster)")
    ing.add_argument("file", help="도구 원본 출력 파일")
    ing.add_argument("--operator", required=True, help="수집 운용자 이름")
    ing.add_argument("--target", default=None,
                     help="출력에 호스트가 없는 도구(gobuster 텍스트)용 대상 폴백")
    ing.add_argument("--db", default="evidence.db")

    apl = sub.add_parser("approvals")
    apl.add_argument("--engagement", default=None); apl.add_argument("--db", default="evidence.db")

    apr = sub.add_parser("approve")
    apr.add_argument("request_id")
    apr.add_argument("--approver", required=True)
    apr.add_argument("--deny", action="store_true", help="승인 대신 거부")
    apr.add_argument("--notify-webhook", default=None, help="승인 결정 알림 웹훅 URL")
    apr.add_argument("--db", default="evidence.db")

    args = p.parse_args(argv)
    try:
        if args.cmd == "scope":
            _scope(args); print("스코프 서명 검증 통과 · 시간창 유효")
        elif args.cmd == "run":
            asyncio.run(_run(args))
        elif args.cmd == "report":
            _report(args)
        elif args.cmd == "report-doc":
            _report_doc(args)
        elif args.cmd == "cleanup":
            _cleanup(args)
        elif args.cmd == "explain":
            _explain(args)
        elif args.cmd == "replay":
            _replay(args)
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
