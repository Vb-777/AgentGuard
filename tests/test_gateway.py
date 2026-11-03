import pytest

from agentguard import Origin, Principal, ToolCall
from agentguard.gateway import ToolDenied

ASHA = Principal("C001", "customer")
STAFF = Principal("D01", "dealer_staff")
REFUND = {"customer_id": "C001", "order_id": "O-1001", "amount_inr": 4500}


def call(tool, args, who=ASHA, **kw):
    return ToolCall(tool, args, who, kw.pop("session", "s1"), **kw)


def test_own_data_is_allowed(gateway):
    assert gateway.execute(call("lookup_orders", {"customer_id": "C001"}))[0]["order_id"] == "O-1001"


def test_cross_customer_access_is_denied(gateway):
    with pytest.raises(ToolDenied) as exc:
        gateway.execute(call("lookup_orders", {"customer_id": "C002"}))
    assert exc.value.decision.rule == "data_scope"


def test_staff_may_read_across_customers(gateway):
    assert len(gateway.execute(call("lookup_orders", {"customer_id": "C002"}, STAFF))) == 2


def test_undeclared_tool_is_denied_even_if_backend_has_it(gateway):
    assert gateway.evaluate(call("export_customer_table", {}, STAFF)).rule == "default_deny"


def test_role_check(gateway):
    assert gateway.evaluate(call("update_inventory", {"sku": "X", "quantity": 1})).rule == "role"


def test_untrusted_origin_cannot_trigger_medium_risk(gateway, backend):
    msg = call("send_customer_message", {"customer_id": "C002", "text": "hi"}, STAFF, origin=Origin.UNTRUSTED)
    with pytest.raises(ToolDenied) as exc:
        gateway.execute(msg)
    assert exc.value.decision.rule == "provenance"
    assert backend.outbox == []


def test_untrusted_origin_may_still_read_low_risk(gateway):
    assert gateway.evaluate(call("lookup_orders", {"customer_id": "C001"}, origin=Origin.UNTRUSTED)).allowed


def test_refund_requires_approval(gateway, backend):
    with pytest.raises(ToolDenied):
        gateway.execute(call("issue_refund", dict(REFUND)))
    assert backend.refunds == []


def test_valid_approval_runs_once(gateway, approvals, backend):
    token = approvals.issue("M01", "issue_refund", REFUND, "C001")
    gateway.execute(call("issue_refund", dict(REFUND), approval_token=token))
    assert len(backend.refunds) == 1
    with pytest.raises(ToolDenied) as exc:
        gateway.execute(call("issue_refund", dict(REFUND), approval_token=token))
    assert "already been used" in exc.value.decision.reason
    assert len(backend.refunds) == 1


def test_approval_is_bound_to_arguments(gateway, approvals):
    token = approvals.issue("M01", "issue_refund", REFUND, "C001")
    d = gateway.evaluate(call("issue_refund", {**REFUND, "amount_inr": 45000}, approval_token=token))
    assert not d.allowed and "arguments" in d.reason


def test_approval_is_bound_to_user(gateway, approvals):
    token = approvals.issue("M01", "issue_refund", REFUND, "C002")
    d = gateway.evaluate(call("issue_refund", dict(REFUND), approval_token=token))
    assert not d.allowed and "different user" in d.reason


def test_approver_role_must_be_authorised(gateway, approvals):
    token = approvals.issue("D01", "issue_refund", REFUND, "C001")
    d = gateway.evaluate(call("issue_refund", dict(REFUND), approval_token=token))
    assert not d.allowed and "may not approve" in d.reason


def test_tampered_token_is_rejected(gateway, approvals):
    token = approvals.issue("M01", "issue_refund", REFUND, "C001")
    body, sig = token.split(".")
    tampered = body[:-2] + ("AA" if body[-2:] != "AA" else "BB") + "." + sig
    assert "signature" in gateway.evaluate(call("issue_refund", dict(REFUND), approval_token=tampered)).reason


def test_expired_approval(gateway, approvals, clock):
    token = approvals.issue("M01", "issue_refund", REFUND, "C001", ttl_seconds=60)
    clock.now += 61
    assert "expired" in gateway.evaluate(call("issue_refund", dict(REFUND), approval_token=token)).reason


def test_amount_cap_applies_even_with_approval(gateway, approvals):
    big = {**REFUND, "amount_inr": 75000}
    token = approvals.issue("M01", "issue_refund", big, "C001")
    assert gateway.evaluate(call("issue_refund", big, approval_token=token)).rule == "amount_limit"


def test_session_rate_limit(gateway):
    claim = {"customer_id": "C001", "description": "noise"}
    for _ in range(3):
        gateway.execute(call("submit_warranty_claim", dict(claim)))
    assert gateway.evaluate(call("submit_warranty_claim", dict(claim))).rule == "rate_limit"
    # A different session has its own budget.
    assert gateway.evaluate(call("submit_warranty_claim", dict(claim), session="s2")).allowed


def test_every_decision_is_audited(gateway):
    gateway.execute(call("lookup_orders", {"customer_id": "C001"}))
    with pytest.raises(ToolDenied):
        gateway.execute(call("lookup_orders", {"customer_id": "C002"}))
    assert [e["decision"] for e in gateway.audit.entries] == ["allow", "deny"]
    assert gateway.audit.verify()[0]
