"""안전 게이트 핵심 3종 증명.
    pytest tests/
"""
from datetime import datetime, timezone, timedelta

from ballista.authorization.scope import EngagementScope
from ballista.policy.action import Action
from ballista.policy.engine import PolicyEngine, Decision
from ballista.attack.refs import AttackRef


def _scope(max_class="modify", denied=None):
    now = datetime.now(timezone.utc)
    return EngagementScope(
        raw={}, engagement_id="ENG-TEST",
        in_scope_cidrs=["10.20.0.0/24"], in_scope_hosts=["app01.internal"],
        out_of_scope_hosts=["10.20.0.1"],
        time_start=now - timedelta(days=1), time_end=now + timedelta(days=1),
        max_action_class=max_class, allowed_techniques=[],
        denied_techniques=denied or ["T1486"], destructive_requires="human",
    )


def _action(target="10.20.0.5", cls="read", tech="T1046"):
    return Action("a1", AttackRef("TA0007", tech), "nmap", target, {}, cls)


def test_out_of_scope_denied():
    d, _ = PolicyEngine().evaluate(_action(target="8.8.8.8"), _scope())
    assert d is Decision.DENY

def test_forbidden_host_denied():
    d, _ = PolicyEngine().evaluate(_action(target="10.20.0.1"), _scope())
    assert d is Decision.DENY

def test_in_scope_allowed():
    d, _ = PolicyEngine().evaluate(_action(), _scope())
    assert d is Decision.ALLOW

def test_action_class_over_limit_denied():
    d, _ = PolicyEngine().evaluate(_action(cls="destructive"), _scope(max_class="modify"))
    assert d is Decision.DENY

def test_denied_technique_blocked():
    d, _ = PolicyEngine().evaluate(_action(tech="T1486", cls="read"), _scope())
    assert d is Decision.DENY

def test_destructive_requires_approval():
    d, _ = PolicyEngine().evaluate(_action(cls="destructive"), _scope(max_class="destructive"))
    assert d is Decision.REQUIRE_APPROVAL
