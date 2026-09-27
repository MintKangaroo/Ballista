"""Policy / Guard Engine.

액션이 실행되기 전 통과해야 하는 판정. 대시보드 '액션 파이프라인'의 로직과 동일.
하나라도 막히면 실행되지 않는다(deny-by-default).
"""

from __future__ import annotations

from enum import Enum

from .action import Action
from ..authorization.scope import EngagementScope


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyEngine:
    def evaluate(self, action: Action, scope: EngagementScope) -> tuple[Decision, str]:
        """(판정, 사유)를 반환."""
        if not scope.is_target_in_scope(action.target):
            return Decision.DENY, f"target out of scope: {action.target}"
        if not scope.is_within_time_window():
            return Decision.DENY, "outside time window"
        if not scope.is_technique_allowed(action.attack.id):
            return Decision.DENY, f"technique not allowed: {action.attack.id}"
        if not scope.class_within_max(action.action_class):
            return Decision.DENY, (f"action_class '{action.action_class}' exceeds "
                                   f"max '{scope.max_action_class}'")
        if action.action_class == "destructive":
            mode = scope.destructive_requires
            if mode == "forbidden":
                return Decision.DENY, "destructive forbidden by scope"
            if mode == "human":
                return Decision.REQUIRE_APPROVAL, "destructive requires human approval"
            # pre_signed
            return Decision.ALLOW, "destructive pre-signed in scope"
        return Decision.ALLOW, "ok"
