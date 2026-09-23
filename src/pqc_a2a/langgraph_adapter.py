"""Optional LangGraph-facing adapter without importing LangGraph itself."""
from __future__ import annotations

from typing import Any, Callable, Awaitable

from .secure_channel import SessionInitiator


class SecureAgentTransport:
    """Adapter usable from a LangGraph node or any async orchestration runtime.

    ``send_record`` is supplied by the application (HTTP, QUIC or relay). The
    adapter keeps graph state separate from transport/session identifiers.
    """
    def __init__(self, session: SessionInitiator, send_record: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]], *, timeout_seconds: float = 10.0):
        if timeout_seconds <= 0: raise ValueError("timeout must be positive")
        self.session, self.send_record, self.timeout_seconds = session, send_record, timeout_seconds

    async def send(self, message: dict[str, Any], *, padding_bucket: int = 0) -> dict[str, Any]:
        import asyncio
        record = self.session.encrypt(message, padding_bucket=padding_bucket)
        response = await asyncio.wait_for(self.send_record(record), timeout=self.timeout_seconds)
        return self.session.decrypt(response)

    def make_node(self, *, input_key: str = "remote_message", output_key: str = "remote_result"):
        async def node(state: dict[str, Any]) -> dict[str, Any]:
            if input_key not in state or not isinstance(state[input_key], dict): raise ValueError("LangGraph state missing secure message")
            result = await self.send(state[input_key])
            return {output_key: result}
        return node


__all__ = ["SecureAgentTransport"]
