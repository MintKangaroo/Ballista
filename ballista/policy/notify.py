"""승인 알림 훅.

승인 요청/결정 이벤트를 외부로 알리는 얇은 계층. 기본은 no-op(테스트·오프라인 안전).
- console_notifier   : 사람이 보게 stdout로 출력
- webhook_notifier(url): JSON을 웹훅으로 POST (stdlib urllib, 실패해도 승인 흐름은 안 막음)

notifier는 event dict 하나를 받는 콜러블이다:
  {"kind": "request"|"decision", "engagement_id", "action_id", "request_id",
   "summary", "status", "approver"?, "approvals"?, "quorum"?}
알림 실패가 승인 게이트를 막으면 안 되므로 예외는 삼킨다.
"""

from __future__ import annotations

import json
import sys
from typing import Callable

Notifier = Callable[[dict], None]


def console_notifier(event: dict) -> None:
    kind = event.get("kind")
    if kind == "request":
        print(f"[알림] 승인 요청 {event['request_id']} · {event['summary']} "
              f"(정족수 {event.get('quorum', 1)})", file=sys.stderr)
    elif kind == "decision":
        extra = ""
        if event.get("status") == "pending":
            extra = f" ({event.get('approvals')}/{event.get('quorum')} 승인)"
        print(f"[알림] {event.get('status', '').upper()} {event['request_id']} "
              f"by {event.get('approver', '?')}{extra}", file=sys.stderr)


def webhook_notifier(url: str, timeout: int = 5) -> Notifier:
    """지정 URL로 이벤트 JSON을 POST하는 notifier를 만든다."""
    import urllib.request

    def _notify(event: dict) -> None:
        try:
            data = json.dumps(event, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                url, data=data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=timeout).close()
        except Exception:
            # 알림 실패가 승인 흐름을 막지 않도록 조용히 무시(감사기록은 evidence에 남음)
            pass

    return _notify
