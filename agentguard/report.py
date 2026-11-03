"""Run the demo scenarios with and without AgentGuard and write a report."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Optional

from .approvals import ApprovalService
from .audit import AuditLog
from .demo.dealer import DealerBackend
from .demo.scenarios import APPROVER_DIRECTORY, OWASP, SCENARIOS
from .gateway import ToolDenied, ToolGateway
from .models import Decision
from .policy import load_policy


@dataclass
class Row:
    sid: str
    title: str
    expect_allowed: bool
    baseline_ran: bool
    decision: Decision
    owasp: Optional[str]
    lazarus: Optional[str]

    @property
    def correct(self) -> bool:
        return self.decision.allowed == self.expect_allowed


def default_policy_path() -> Path:
    return Path(str(resources.files("agentguard.demo").joinpath("dealer_service.toml")))


def run_demo(out_dir: Optional[str | Path] = None) -> tuple[list[Row], AuditLog]:
    policy = load_policy(default_policy_path())
    svc = ApprovalService(secrets.token_bytes(32), APPROVER_DIRECTORY)

    # Baseline: an unguarded agent runs whatever tool call it proposes.
    unguarded = DealerBackend().tools()
    baseline: dict[str, bool] = {}
    base_svc = ApprovalService(secrets.token_bytes(32), APPROVER_DIRECTORY)
    for sc in SCENARIOS:
        call = sc.build(base_svc)
        try:
            unguarded[call.tool](**call.args)
            baseline[sc.sid] = True
        except Exception:
            baseline[sc.sid] = False

    # Guarded: the same proposals pass through AgentGuard.
    audit_path = None
    if out_dir:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        audit_path = out / "audit.jsonl"
        if audit_path.exists():
            audit_path.unlink()
    audit = AuditLog(audit_path)
    gateway = ToolGateway(policy, DealerBackend().tools(), svc, audit)

    rows: list[Row] = []
    for sc in SCENARIOS:
        call = sc.build(svc)
        try:
            gateway.execute(call)
            decision = audit_decision(gateway)
        except ToolDenied as exc:
            decision = exc.decision
        rows.append(Row(sc.sid, sc.title, sc.expect_allowed, baseline[sc.sid], decision, sc.owasp, sc.lazarus))
    return rows, audit


def audit_decision(gateway: ToolGateway) -> Decision:
    last = gateway.audit.entries[-1]
    return Decision(last["decision"] == "allow", last["rule"], last["reason"], last["tool"])


def render_markdown(rows: list[Row], audit: AuditLog) -> str:
    risky = [r for r in rows if not r.expect_allowed]
    legit = [r for r in rows if r.expect_allowed]
    base_risky = sum(r.baseline_ran for r in risky)
    guard_risky = sum(r.decision.allowed for r in risky)
    guard_legit = sum(r.decision.allowed for r in legit)
    ok, msg = audit.verify()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# AgentGuard demo report",
        "",
        f"Generated {stamp} · policy: `dealer_service.toml` · {len(rows)} proposed tool calls",
        "",
        "## Summary",
        "",
        "| | Unguarded agent | With AgentGuard |",
        "| --- | --- | --- |",
        f"| Unauthorised actions executed | **{base_risky} of {len(risky)}** | **{guard_risky} of {len(risky)}** |",
        f"| Legitimate actions executed | {len(legit)} of {len(legit)} | {guard_legit} of {len(legit)} |",
        f"| Audit trail | none | {msg if ok else 'BROKEN: ' + msg} |",
        "",
        "## Decisions",
        "",
        "| ID | Proposed action | Unguarded | AgentGuard | Rule | Reason | Risk mapping |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        verdict = "allow" if r.decision.allowed else "**deny**"
        if not r.correct:
            verdict += " ⚠ unexpected"
        mapping = OWASP.get(r.owasp, "") if r.owasp else ""
        if r.lazarus:
            mapping = f"{mapping}; arena: {r.lazarus}" if mapping else f"arena: {r.lazarus}"
        lines.append(
            f"| {r.sid} | {r.title} | {'ran' if r.baseline_ran else 'failed'} | {verdict} | "
            f"`{r.decision.rule}` | {r.decision.reason} | {mapping} |"
        )
    lines += [
        "",
        "## How to read this",
        "",
        "The unguarded column shows what happens when an agent's proposed tool call is executed directly. "
        "Every check AgentGuard applies runs in code, outside the model: identity comes from the session, "
        "approvals must be signed by the approval service and bound to the exact call, and instructions "
        "found inside content the agent read cannot trigger medium- or high-risk actions.",
        "",
    ]
    return "\n".join(lines)
