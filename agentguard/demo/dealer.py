"""A simulated dealer-service backend. All data is fictional and in memory."""

from __future__ import annotations

import copy
from typing import Any

SEED: dict[str, Any] = {
    "customers": {
        "C001": {"name": "Asha Rao", "email": "asha@example.com"},
        "C002": {"name": "Rohan Mehta", "email": "rohan@example.com"},
    },
    "orders": [
        {"order_id": "O-1001", "customer_id": "C001", "item": "Service kit 150cc", "amount_inr": 4500},
        {"order_id": "O-1002", "customer_id": "C002", "item": "Brake pad set", "amount_inr": 2200},
        {"order_id": "O-1003", "customer_id": "C002", "item": "Helmet, full face", "amount_inr": 6800},
    ],
    "warranties": {
        "C001": {"vehicle": "Scooter 125", "valid_until": "2027-08-31"},
        "C002": {"vehicle": "Motorcycle 155", "valid_until": "2026-12-15"},
    },
    "inventory": {"BRK-PAD-01": 40, "OIL-FLT-02": 120},
}


class DealerBackend:
    def __init__(self) -> None:
        self.db = copy.deepcopy(SEED)
        self.refunds: list[dict[str, Any]] = []
        self.claims: list[dict[str, Any]] = []
        self.outbox: list[dict[str, Any]] = []

    # Each method is a "tool" the agent can propose to call.
    def lookup_orders(self, customer_id: str) -> list[dict[str, Any]]:
        return [o for o in self.db["orders"] if o["customer_id"] == customer_id]

    def check_warranty(self, customer_id: str) -> dict[str, Any]:
        return self.db["warranties"].get(customer_id, {})

    def submit_warranty_claim(self, customer_id: str, description: str) -> dict[str, Any]:
        claim = {"claim_id": f"W-{len(self.claims) + 1:04d}", "customer_id": customer_id, "description": description}
        self.claims.append(claim)
        return claim

    def issue_refund(self, customer_id: str, order_id: str, amount_inr: float) -> dict[str, Any]:
        refund = {"customer_id": customer_id, "order_id": order_id, "amount_inr": amount_inr}
        self.refunds.append(refund)
        return refund

    def update_inventory(self, sku: str, quantity: int) -> dict[str, Any]:
        self.db["inventory"][sku] = quantity
        return {"sku": sku, "quantity": quantity}

    def send_customer_message(self, customer_id: str, text: str) -> dict[str, Any]:
        msg = {"to": customer_id, "text": text}
        self.outbox.append(msg)
        return msg

    def tools(self) -> dict[str, Any]:
        return {
            "lookup_orders": self.lookup_orders,
            "check_warranty": self.check_warranty,
            "submit_warranty_claim": self.submit_warranty_claim,
            "issue_refund": self.issue_refund,
            "update_inventory": self.update_inventory,
            "send_customer_message": self.send_customer_message,
            # Present in the backend but deliberately NOT in the policy:
            "export_customer_table": lambda: copy.deepcopy(self.db["customers"]),
        }
