"""방어지향 어시스턴트 — LLM 클라이언트 연결.

assistant.py의 프롬프트 빌더가 만든 프롬프트를 실제 LLM(Claude)에 보낸다.
역할은 SYSTEM_ROLE로 사후 해석·방어·학습에 고정돼 있어(공격 다음 수·익스플로잇
방법은 거절), 여기서 새로 완화하지 않는다.

의존은 지연 로딩한다: anthropic SDK나 API 키가 없어도 import·프롬프트 생성(dry-run)은
동작하고, 실제 전송(--send)할 때만 SDK/자격증명이 필요하다.

기본 모델: claude-opus-5 (필요 시 --model로 변경).
자격증명: ANTHROPIC_API_KEY 또는 `ant auth login` 프로필(SDK가 환경에서 해석).
"""

from __future__ import annotations

DEFAULT_MODEL = "claude-opus-5"


def sdk_available() -> bool:
    """anthropic SDK가 설치돼 있는지."""
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def ask_claude(prompt: str, model: str = DEFAULT_MODEL, max_tokens: int = 2000) -> str:
    """프롬프트를 Claude에 보내고 텍스트 응답을 반환.

    호출 시점에만 anthropic SDK/자격증명이 필요하다. 방어 역할은 프롬프트 자체
    (SYSTEM_ROLE 포함)에 박혀 있다.
    """
    import anthropic  # 지연 import — 없으면 여기서만 실패

    client = anthropic.Anthropic()   # 환경에서 자격증명 해석
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in resp.content if b.type == "text").strip()
