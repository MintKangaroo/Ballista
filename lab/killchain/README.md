# lab/killchain — 합성 킬체인 시연 (시뮬레이션 전용)

실제 공격 없이, 공격 계열 어댑터(exploit/credential/lateral)를 **시뮬레이션 모드**로
돌려 정찰→초기접근→자격증명→측면이동의 풀 킬체인 evidence를 만든다. 대시보드
공격경로 그래프·리포트·replay를 풀 체인으로 시연하는 용도.

> 실제 `run()`은 `NotImplementedError` 스텁 그대로다(INV-2). `--simulate`는 별도
> `simulate()` 경로로 **명백히 '합성'으로 표시된 가짜 결과**만 만든다. 외부 도구 호출,
> 페이로드 생성, 자격증명 값이 전혀 없다. evidence에는 `simulated: true`로 낙인된다.

```bash
python sign_scope.py lab/killchain/scope.yaml lab/killchain/keys
python -m ballista.cli run lab/killchain/scope.yaml lab/killchain/keys \
    lab/killchain/actions.yaml.json --db lab/killchain/evidence.db --simulate
python -m ballista.cli dashboard lab/killchain/scope.yaml lab/killchain/keys \
    --db lab/killchain/evidence.db --out lab/killchain/dashboard.json
python -m ballista.cli replay ENG-DEMO-KILLCHAIN --db lab/killchain/evidence.db --out replay.yaml
```

실측 그래프: `entry → 10.99.0.10` (T1190·T1003) → `10.99.0.20` (T1021.002), 자격증명 노드 `cred-demo-1`.
