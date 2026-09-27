"""리포트 생성기 — evidence + 커버리지 → 기술/경영 리포트 초안(Markdown).

전부 사후 분석·리포팅이다. 공격 실행 없음 — 이미 기록된 evidence를 읽어
사람이 읽는 문서로 조립할 뿐이다(INV 준수).

구성:
  build_markdown_report() : 경영 요약 + 기술 상세를 담은 Markdown 문자열 생성
  write_report()          : 파일로 저장(.md). --pdf 요청 시 pandoc이 있으면 PDF도 시도.

방어지향 어시스턴트(assistant/)와 연결:
  with_prompts=True 이면 부록에 build_summary_prompt/build_gap_prompt 결과(LLM에
  그대로 넣을 프롬프트)를 실어, 운용자가 원하는 LLM 클라이언트로 서사를 보강할 수 있다.

의존:
  ballista/dashboard/binding.py  build_dashboard_data (집계·직렬화 재사용)
  ballista/reporter/reporter.py  coverage_summary, detection_gaps
  ballista/assistant/assistant.py  build_summary_prompt, build_gap_prompt
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone

from ..dashboard.binding import build_dashboard_data, ATTACK_NAMES
from ..reporter.reporter import coverage_summary, detection_gaps
from ..assistant.assistant import build_summary_prompt, build_gap_prompt

_SEV_LABEL = {"crit": "Critical", "high": "High", "med": "Medium", "low": "Low/Info"}


def _md_escape(s) -> str:
    """표 셀에 들어갈 값에서 파이프/개행을 무해화."""
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list]) -> str:
    """Markdown 표 생성. rows가 비면 '(없음)' 한 줄."""
    head = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    if not rows:
        empty = "| " + " | ".join(["(없음)"] + [""] * (len(headers) - 1)) + " |"
        return "\n".join([head, sep, empty])
    body = "\n".join("| " + " | ".join(_md_escape(c) for c in r) + " |" for r in rows)
    return "\n".join([head, sep, body])


def build_markdown_report(store, scope, engagement_id: str,
                          detected_technique_ids=None,
                          with_prompts: bool = False) -> str:
    """evidence 체인 → 기술/경영 리포트(Markdown 문자열)."""
    detected = set(detected_technique_ids or set())
    data = build_dashboard_data(store, scope, engagement_id, detected)
    summary = coverage_summary(store, engagement_id)
    gaps = detection_gaps(summary, detected)
    records = list(store.records(engagement_id))
    chain_ok = store.verify_chain(engagement_id)

    eng = data["engagement"]
    scp = data["SCOPE"]
    raw = getattr(scope, "raw", {}) or {}
    meta = raw.get("engagement") or {}
    kpi = {k["lab"]: k for k in data["KPI"]}
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")

    L: list[str] = []
    a = L.append

    # ── 표지 ──
    a(f"# 침투 테스트 리포트 — {eng['id']}")
    a("")
    a(f"**교전명**: {meta.get('name', '-')}  ")
    a(f"**승인자**: {meta.get('authorized_by', '-')}  ")
    a(f"**RoE 문서**: {meta.get('roe_document_ref', '-')}  ")
    a(f"**생성 시각**: {now}  ")
    a(f"**증거 체인 무결성**: {'✅ OK' if chain_ok else '❌ 위반 감지'}  ")
    a("")
    a("> 이 리포트는 Ballista가 append-only 해시 체인에 기록한 evidence를 사후 집계해 "
      "자동 생성한 초안이다. 수치·타임라인은 위·변조 검증된 기록에서 나온다.")
    a("")

    # ── 1. 경영 요약 ──
    a("## 1. 경영 요약 (Executive Summary)")
    a("")
    a(f"- **실행된 액션**: {kpi['EXECUTED ACTIONS']['val']}건")
    a(f"- **성공 경로(권한 변경 이상)**: {kpi['SUCCESSFUL PATHS']['val']}개 "
      f"({kpi['SUCCESSFUL PATHS']['meta']})")
    a(f"- **발견 취약점**: {kpi['FINDINGS']['val']}건 ({kpi['FINDINGS']['meta']})")
    a(f"- **탐지 공백**: {kpi['DETECTION GAPS']['val']}건 — 공격이 성공했으나 방어 탐지가 없던 기법")
    a(f"- **증거 체인**: {kpi['CHAIN INTEGRITY']['val']} ({kpi['CHAIN INTEGRITY']['meta']})")
    a("")
    if gaps:
        a(f"이번 교전에서 **탐지 공백 {len(gaps)}건**이 확인됐다. 성공한 기법이 방어 관제에 "
          "포착되지 않았다는 뜻으로, 우선 보완 대상이다(6장 참조).")
    else:
        a("이번 교전에서 미탐지 성공 기법(탐지 공백)은 확인되지 않았다.")
    a("")

    # ── 2. 스코프 & RoE ──
    a("## 2. 스코프 & 교전 규칙 (RoE)")
    a("")
    a(f"- **시간창**: {scp['time_window']}")
    a(f"- **최대 행위 등급**: {scp['max_class']}")
    a(f"- **서명**: {scp['signature']} (key_id 검증 통과 — INV-3)")
    a(f"- **범위 내**: {', '.join(scp['in_scope']) or '-'}")
    a(f"- **범위 외**: {', '.join(scp['out_of_scope']) or '-'}")
    a("")

    # ── 3. ATT&CK 킬체인 커버리지 ──
    a("## 3. ATT&CK 킬체인 커버리지")
    a("")
    a(_table(["Tactic", "ID", "시도", "성공"],
             [[k["t"], k["id"], k["att"], k["ok"]] for k in data["KILLCHAIN"]]))
    a("")

    # ── 4. 실행 액션 타임라인 ──
    a("## 4. 실행 액션 타임라인")
    a("")
    rows = []
    for f in data["FEED"]:
        rows.append([f["tm"], f["d1"], f["d2"], f["rc"], f.get("cls", "")])
    # FEED는 최신순 → 타임라인은 시간순으로 뒤집어 표시
    rows.reverse()
    a(_table(["시각", "행위", "도구·기법", "결과", "등급"], rows))
    a("")

    # ── 5. 발견 취약점 ──
    a("## 5. 발견 취약점")
    a("")
    a(_table(["심각도", "취약점", "템플릿/ID", "호스트"],
             [[_SEV_LABEL.get(v["sev"], v["sev"]), v["v1"], v["v2"], v["host"]]
              for v in data["VULNS"]]))
    a("")

    # ── 6. 탐지 공백 & 방어 권고 ──
    a("## 6. 탐지 공백 & 방어 권고")
    a("")
    if gaps:
        grows = []
        for g in gaps:
            name = ATTACK_NAMES.get(g["id"], g["id"])
            grows.append([g["id"], name, g["successes"], g.get("last_seen", "-")])
        a(_table(["기법 ID", "이름", "성공 횟수", "마지막 관측"], grows))
        a("")
        a("**권고**: 위 기법들은 성공했으나 대응하는 탐지 이벤트가 없었다. "
          "해당 기법의 탐지 룰(로그 소스·시그니처·상관분석)을 우선 보강할 것. "
          "항목별 세부 방어책은 방어 어시스턴트 프롬프트(부록)로 생성할 수 있다.")
    else:
        a("탐지 공백 없음 — 성공한 기법은 모두 방어 관제에 포착됐다(또는 성공 기법 없음).")
    a("")

    # ── 7. 증거 무결성 ──
    a("## 7. 증거 무결성")
    a("")
    a(f"- 총 evidence 레코드: **{len(records)}건**")
    a(f"- 해시 체인 재검증: **{'무결(OK)' if chain_ok else '위반 감지(FAIL)'}**")
    a("- 각 레코드 해시 = sha256(canonical(record) + prev_hash). 중간 위·변조 시 이후 전부가 깨진다.")
    a("")

    # ── 부록: 어시스턴트 프롬프트 ──
    if with_prompts:
        a("## 부록 A. 방어 어시스턴트 프롬프트")
        a("")
        a("아래 프롬프트를 원하는 LLM 클라이언트에 그대로 넣으면 evidence 기반 서사·방어 권고를 "
          "보강할 수 있다. (역할이 사후 해석·방어·학습으로 고정돼 공격 다음 수는 생성하지 않는다.)")
        a("")
        a("### A.1 교전 요약 프롬프트")
        a("")
        a("```")
        a(build_summary_prompt(data))
        a("```")
        a("")
        a("### A.2 탐지 공백 방어 권고 프롬프트")
        a("")
        a("```")
        a(build_gap_prompt(gaps))
        a("```")
        a("")

    a("---")
    a("*Ballista 리포트 생성기 · evidence 기반 자동 초안*")
    return "\n".join(L) + "\n"


def write_report(store, scope, engagement_id: str, out_path: str,
                 detected_technique_ids=None, with_prompts: bool = False,
                 pdf: bool = False) -> dict:
    """리포트를 파일로 저장. 반환: {md, pdf?}.

    pdf=True이고 pandoc이 설치돼 있으면 PDF도 생성(없으면 md만, 안내는 호출부 몫).
    """
    md = build_markdown_report(store, scope, engagement_id,
                               detected_technique_ids, with_prompts)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)
    result = {"md": out_path, "pdf": None, "pdf_note": None}

    if pdf:
        pandoc = shutil.which("pandoc")
        if not pandoc:
            result["pdf_note"] = "pandoc 미설치 — PDF 생략(.md만 생성). `apt install pandoc`."
        else:
            pdf_path = out_path.rsplit(".", 1)[0] + ".pdf"
            try:
                subprocess.run([pandoc, out_path, "-o", pdf_path],
                               check=True, capture_output=True)
                result["pdf"] = pdf_path
            except subprocess.CalledProcessError as e:
                result["pdf_note"] = f"pandoc 변환 실패: {e.stderr.decode(errors='replace')[:200]}"
    return result
