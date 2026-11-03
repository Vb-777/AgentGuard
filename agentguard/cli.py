"""Command-line interface.

    python -m agentguard demo [--out reports]
    python -m agentguard verify-log reports/audit.jsonl
    python -m agentguard check-policy path/to/policy.toml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .audit import read_entries, verify_entries
from .policy import load_policy
from .report import render_markdown, run_demo


def _demo(args: argparse.Namespace) -> int:
    rows, audit = run_demo(args.out)
    report = render_markdown(rows, audit)
    out = Path(args.out)
    (out / "demo_report.md").write_text(report, encoding="utf-8")

    width = max(len(r.title) for r in rows)
    print(f"{'ID':<4} {'Proposed action':<{width}}  {'Verdict':<7}  Rule")
    for r in rows:
        verdict = "ALLOW" if r.decision.allowed else "DENY"
        flag = "" if r.correct else "   <-- unexpected"
        print(f"{r.sid:<4} {r.title:<{width}}  {verdict:<7}  {r.decision.rule}{flag}")
    risky = [r for r in rows if not r.expect_allowed]
    print()
    print(f"Unauthorised actions executed: unguarded {sum(r.baseline_ran for r in risky)}/{len(risky)}, "
          f"AgentGuard {sum(r.decision.allowed for r in risky)}/{len(risky)}")
    print(audit.verify()[1])
    print(f"Report: {out / 'demo_report.md'}   Audit log: {out / 'audit.jsonl'}")
    return 0 if all(r.correct for r in rows) else 1


def _verify(args: argparse.Namespace) -> int:
    ok, msg = verify_entries(read_entries(args.path))
    print(msg)
    return 0 if ok else 2


def _check(args: argparse.Namespace) -> int:
    policy = load_policy(args.path)
    print(f"Policy for agent {policy.agent!r}: {len(policy.tools)} tools")
    for rule in policy.tools.values():
        extras = []
        if rule.owner_arg:
            extras.append(f"scoped by {rule.owner_arg}")
        if rule.requires_approval:
            extras.append("approval: " + "/".join(rule.approver_roles))
        if rule.max_amount is not None:
            extras.append(f"max {rule.max_amount:g}")
        if rule.max_calls_per_session:
            extras.append(f"{rule.max_calls_per_session}/session")
        if rule.blocks_untrusted():
            extras.append("user-initiated only")
        print(f"  {rule.name:<24} {rule.risk:<6} roles={','.join(rule.allowed_roles)}  {'; '.join(extras)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard", description="Policy gateway for AI agent tool calls")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("demo", help="run the dealer-service demo and write a report")
    p.add_argument("--out", default="reports", help="output folder (default: reports)")
    p.set_defaults(func=_demo)

    p = sub.add_parser("verify-log", help="check an audit log's hash chain")
    p.add_argument("path")
    p.set_defaults(func=_verify)

    p = sub.add_parser("check-policy", help="validate and summarise a policy file")
    p.add_argument("path")
    p.set_defaults(func=_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
