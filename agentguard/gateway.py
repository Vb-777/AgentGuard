"""The tool gateway: every tool call the agent proposes passes through here.

Checks run in a fixed order and the first failure wins:

  1. default-deny       tool must be declared in the policy
  2. role               principal's role must be allowed to use the tool
  3. provenance         medium/high-risk calls may not come from untrusted content
  4. data scope         owner argument must match the principal (no cross-customer access)
  5. amount limit       numeric cap on high-impact amounts
  6. rate limit         per-session call budget
  7. approval           signed, bound, single-use approval when required

Every decision, allowed or denied, is written to the audit log.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Optional

from .approvals import ApprovalService
from .audit import AuditLog
from .models import Decision, Origin, ToolCall
from .policy import Policy

ToolFn = Callable[..., Any]


class ToolDenied(PermissionError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(f"{decision.tool}: {decision.reason}")
        self.decision = decision


class ToolGateway:
    def __init__(
        self,
        policy: Policy,
        tools: dict[str, ToolFn],
        approvals: Optional[ApprovalService] = None,
        audit: Optional[AuditLog] = None,
    ) -> None:
        self.policy = policy
        self.tools = dict(tools)
        self.approvals = approvals
        self.audit = audit or AuditLog()
        self._calls: Counter[tuple[str, str]] = Counter()

    # ------------------------------------------------------------------
    def evaluate(self, call: ToolCall) -> Decision:
        rule = self.policy.rule_for(call.tool)
        if rule is None or call.tool not in self.tools:
            return Decision(False, "default_deny", "tool is not declared in the policy", call.tool)

        def deny(rule_name: str, reason: str, **details: Any) -> Decision:
            return Decision(False, rule_name, reason, call.tool, rule.risk, details)

        if call.principal.role not in rule.allowed_roles:
            return deny("role", f"role {call.principal.role!r} may not call {call.tool!r}")

        if call.origin == Origin.UNTRUSTED and rule.blocks_untrusted():
            return deny(
                "provenance",
                "instruction came from untrusted content; a "
                f"{rule.risk}-risk action needs a request from the user",
            )

        if rule.owner_arg:
            owner = call.args.get(rule.owner_arg)
            if owner is None:
                return deny("data_scope", f"missing required argument {rule.owner_arg!r}")
            if owner != call.principal.user_id and call.principal.role not in rule.cross_scope_roles:
                return deny(
                    "data_scope",
                    f"{call.principal.user_id} may not act on data owned by {owner}",
                )

        if rule.amount_arg and rule.max_amount is not None:
            amount = call.args.get(rule.amount_arg)
            if not isinstance(amount, (int, float)) or amount <= 0:
                return deny("amount_limit", f"{rule.amount_arg!r} must be a positive number")
            if amount > rule.max_amount:
                return deny("amount_limit", f"{amount} exceeds the limit of {rule.max_amount}")

        if rule.max_calls_per_session is not None:
            used = self._calls[(call.session_id, call.tool)]
            if used >= rule.max_calls_per_session:
                return deny("rate_limit", f"session limit of {rule.max_calls_per_session} calls reached")

        if rule.requires_approval:
            if self.approvals is None:
                return deny("approval", "approval required but no approval service is configured")
            result = self.approvals.verify(call.approval_token, call, rule.approver_roles)
            if not result.valid:
                return deny("approval", result.reason)
            return Decision(
                True,
                "approved",
                f"approved by {result.approver} ({result.approver_role})",
                call.tool,
                rule.risk,
                {"approver": result.approver},
            )

        return Decision(True, "allowed", "within policy", call.tool, rule.risk)

    # ------------------------------------------------------------------
    def execute(self, call: ToolCall) -> Any:
        """Evaluate, log, and run the tool only if allowed."""
        decision = self.evaluate(call)
        self._log(call, decision)
        if not decision.allowed:
            raise ToolDenied(decision)
        result = self.tools[call.tool](**call.args)
        self._calls[(call.session_id, call.tool)] += 1
        if call.approval_token and self.approvals is not None:
            self.approvals.consume(call.approval_token)
        return result

    def _log(self, call: ToolCall, decision: Decision) -> None:
        self.audit.append(
            {
                "session": call.session_id,
                "principal": call.principal.user_id,
                "role": call.principal.role,
                "origin": call.origin.value,
                "tool": call.tool,
                "args": call.args,
                "decision": "allow" if decision.allowed else "deny",
                "rule": decision.rule,
                "reason": decision.reason,
            }
        )
