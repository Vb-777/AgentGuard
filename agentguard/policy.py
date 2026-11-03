"""Policy loading. Policies are TOML files: one table per tool.

Anything not listed is denied (default-deny).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

RISK_LEVELS = ("low", "medium", "high")


@dataclass(frozen=True)
class ToolRule:
    name: str
    risk: str = "medium"
    allowed_roles: tuple[str, ...] = ()
    # Argument that names the data owner (e.g. customer_id). If set, it must
    # equal the principal's user_id unless the principal's role is listed in
    # cross_scope_roles.
    owner_arg: Optional[str] = None
    cross_scope_roles: tuple[str, ...] = ()
    requires_approval: bool = False
    approver_roles: tuple[str, ...] = ()
    amount_arg: Optional[str] = None
    max_amount: Optional[float] = None
    max_calls_per_session: Optional[int] = None
    # Calls whose instruction came from untrusted content are refused for
    # this tool. Defaults to True for medium and high risk tools.
    deny_untrusted_origin: Optional[bool] = None

    def blocks_untrusted(self) -> bool:
        if self.deny_untrusted_origin is not None:
            return self.deny_untrusted_origin
        return self.risk in ("medium", "high")


@dataclass(frozen=True)
class Policy:
    agent: str
    tools: dict[str, ToolRule] = field(default_factory=dict)

    def rule_for(self, tool: str) -> Optional[ToolRule]:
        return self.tools.get(tool)


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def policy_from_dict(data: dict) -> Policy:
    agent = data.get("agent", {}).get("name", "unnamed-agent")
    tools: dict[str, ToolRule] = {}
    for name, spec in data.get("tools", {}).items():
        risk = spec.get("risk", "medium")
        if risk not in RISK_LEVELS:
            raise ValueError(f"tool {name!r}: risk must be one of {RISK_LEVELS}, got {risk!r}")
        rule = ToolRule(
            name=name,
            risk=risk,
            allowed_roles=_as_tuple(spec.get("allowed_roles")),
            owner_arg=spec.get("owner_arg"),
            cross_scope_roles=_as_tuple(spec.get("cross_scope_roles")),
            requires_approval=bool(spec.get("requires_approval", False)),
            approver_roles=_as_tuple(spec.get("approver_roles")),
            amount_arg=spec.get("amount_arg"),
            max_amount=spec.get("max_amount"),
            max_calls_per_session=spec.get("max_calls_per_session"),
            deny_untrusted_origin=spec.get("deny_untrusted_origin"),
        )
        if rule.requires_approval and not rule.approver_roles:
            raise ValueError(f"tool {name!r}: requires_approval needs approver_roles")
        if not rule.allowed_roles:
            raise ValueError(f"tool {name!r}: allowed_roles must not be empty")
        tools[name] = rule
    return Policy(agent=agent, tools=tools)


def load_policy(path: str | Path) -> Policy:
    with open(path, "rb") as fh:
        return policy_from_dict(tomllib.load(fh))
