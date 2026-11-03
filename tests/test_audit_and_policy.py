import json

import pytest

from agentguard import AuditLog
from agentguard.audit import read_entries, verify_entries
from agentguard.policy import policy_from_dict
from agentguard.report import run_demo


def _log(tmp_path, n=3):
    log = AuditLog(tmp_path / "audit.jsonl", clock=lambda: 1.0)
    for i in range(n):
        log.append({"tool": "t", "decision": "allow", "i": i})
    return tmp_path / "audit.jsonl"


def test_intact_log_verifies(tmp_path):
    ok, msg = verify_entries(read_entries(_log(tmp_path)))
    assert ok and "3 entries" in msg


def test_edited_entry_is_detected(tmp_path):
    path = _log(tmp_path)
    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["decision"] = "deny"
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n")
    ok, msg = verify_entries(read_entries(path))
    assert not ok and "entry 2" in msg


def test_deleted_entry_is_detected(tmp_path):
    path = _log(tmp_path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not verify_entries(read_entries(path))[0]


def test_log_resumes_chain_from_file(tmp_path):
    path = _log(tmp_path, 2)
    AuditLog(path, clock=lambda: 2.0).append({"tool": "t", "decision": "deny"})
    ok, msg = verify_entries(read_entries(path))
    assert ok and "3 entries" in msg


def test_policy_rejects_bad_risk():
    with pytest.raises(ValueError):
        policy_from_dict({"tools": {"x": {"risk": "extreme", "allowed_roles": ["a"]}}})


def test_policy_requires_approvers_when_approval_needed():
    with pytest.raises(ValueError):
        policy_from_dict({"tools": {"x": {"allowed_roles": ["a"], "requires_approval": True}}})


def test_demo_matches_expectations(tmp_path):
    rows, audit = run_demo(tmp_path)
    assert all(r.correct for r in rows)
    risky = [r for r in rows if not r.expect_allowed]
    assert all(r.baseline_ran for r in risky)
    assert not any(r.decision.allowed for r in risky)
    assert audit.verify()[0]
