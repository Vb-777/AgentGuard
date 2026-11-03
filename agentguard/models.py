"""Core data types shared across AgentGuard."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Origin(str, Enum):
    """Where the instruction that produced a tool call came from.

    USER      - the authenticated user's own request in this session.
    UNTRUSTED - text the agent *read* (an email, attachment, web page, tool
                output). Content is data, never authority.
    """

    USER = "user"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class Principal:
    """The authenticated identity the agent is acting for.

    This comes from the application's login/session layer, never from
    anything the model says or reads.
    """

    user_id: str
    role: str


@dataclass
class ToolCall:
    """A tool call proposed by the agent."""

    tool: str
    args: dict[str, Any]
    principal: Principal
    session_id: str
    origin: Origin = Origin.USER
    approval_token: Optional[str] = None

    def args_digest(self) -> str:
        return canonical_digest(self.args)


@dataclass
class Decision:
    allowed: bool
    rule: str
    reason: str
    tool: str
    risk: str = "unknown"
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "rule": self.rule,
            "reason": self.reason,
            "tool": self.tool,
            "risk": self.risk,
            **({"details": self.details} if self.details else {}),
        }


def canonical_json(obj: Any) -> str:
    """Deterministic JSON so the same data always hashes the same way."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_digest(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
