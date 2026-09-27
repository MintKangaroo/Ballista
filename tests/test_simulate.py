"""시뮬레이션 어댑터 테스트 — 실제 run()은 스텁 유지, simulate()는 합성 결과."""

from __future__ import annotations

import asyncio

import pytest

from ballista.adapters.exploit import ExploitAdapter
from ballista.adapters.credential import CredentialAdapter
from ballista.adapters.lateral import LateralAdapter


class _Scope:
    def is_target_in_scope(self, t):
        return t == "10.0.0.5"


ADAPTERS = [ExploitAdapter, CredentialAdapter, LateralAdapter]


@pytest.mark.parametrize("cls", ADAPTERS)
def test_real_run_still_stub(cls):
    """INV-2: 실제 run()은 여전히 NotImplementedError."""
    a = cls(_Scope())
    with pytest.raises(NotImplementedError):
        asyncio.run(a.run({"target": "10.0.0.5"}))


@pytest.mark.parametrize("cls", ADAPTERS)
def test_simulate_returns_labeled_fake(cls):
    a = cls(_Scope())
    assert a.supports_simulation is True
    res = a.simulate({"target": "10.0.0.5"})
    assert res.returncode == 0
    assert res.parsed["simulated"] is True
    assert res.raw_output == b""                 # 원본 출력 없음(실제 실행 아님)
    assert "합성" in res.parsed["warning"]
    assert res.attack.id                          # ATT&CK 매핑은 유지


@pytest.mark.parametrize("cls", ADAPTERS)
def test_simulate_still_scope_gated(cls):
    """시뮬레이션도 스코프 게이팅은 적용 — 범위 밖이면 거부."""
    a = cls(_Scope())
    with pytest.raises(PermissionError):
        a.simulate({"target": "8.8.8.8"})
