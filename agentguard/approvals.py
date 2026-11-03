"""Signed, single-use approvals for high-impact actions.

In Lazarus Arena, a break often came from convincing the model that someone
had already approved an action. AgentGuard removes that option: an approval
is only valid if it is a token signed by the approval service, bound to the
exact tool, arguments and requesting user, unexpired, and not used before.
What the model *believes* about approvals is irrelevant.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .models import ToolCall, canonical_digest, canonical_json


@dataclass(frozen=True)
class ApprovalResult:
    valid: bool
    reason: str
    approver: Optional[str] = None
    approver_role: Optional[str] = None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


class ApprovalService:
    """Issues and verifies approval tokens.

    ``directory`` maps approver user_id -> role. It is the source of truth
    for who may approve; roles are looked up here at verification time.
    """

    def __init__(
        self,
        secret: bytes,
        directory: dict[str, str],
        clock: Callable[[], float] = time.time,
    ) -> None:
        if len(secret) < 16:
            raise ValueError("secret must be at least 16 bytes")
        self._secret = secret
        self._directory = dict(directory)
        self._clock = clock
        self._used_nonces: set[str] = set()

    # -- issuing -----------------------------------------------------------
    def issue(
        self,
        approver_id: str,
        tool: str,
        args: dict,
        subject_user_id: str,
        ttl_seconds: int = 900,
    ) -> str:
        if approver_id not in self._directory:
            raise PermissionError(f"{approver_id!r} is not a registered approver")
        payload = {
            "tool": tool,
            "args_sha256": canonical_digest(args),
            "subject": subject_user_id,
            "approver": approver_id,
            "exp": int(self._clock()) + int(ttl_seconds),
            "nonce": secrets.token_hex(12),
        }
        body = _b64(canonical_json(payload).encode("utf-8"))
        sig = _b64(self._sign(body))
        return f"{body}.{sig}"

    # -- verifying ---------------------------------------------------------
    def verify(self, token: Optional[str], call: ToolCall, allowed_roles: tuple[str, ...]) -> ApprovalResult:
        if not token:
            return ApprovalResult(False, "no approval token supplied")
        try:
            body, sig = token.split(".", 1)
            expected = self._sign(body)
            if not hmac.compare_digest(expected, _unb64(sig)):
                return ApprovalResult(False, "approval signature is invalid")
            payload = json.loads(_unb64(body))
        except (ValueError, json.JSONDecodeError):
            return ApprovalResult(False, "approval token is malformed")

        approver = payload.get("approver")
        role = self._directory.get(approver)
        if role is None:
            return ApprovalResult(False, "approver is no longer registered", approver)
        if role not in allowed_roles:
            return ApprovalResult(False, f"approver role {role!r} may not approve {call.tool!r}", approver, role)
        if payload.get("tool") != call.tool:
            return ApprovalResult(False, "approval was issued for a different tool", approver, role)
        if payload.get("args_sha256") != call.args_digest():
            return ApprovalResult(False, "approval does not match these arguments", approver, role)
        if payload.get("subject") != call.principal.user_id:
            return ApprovalResult(False, "approval was issued for a different user", approver, role)
        if int(payload.get("exp", 0)) < int(self._clock()):
            return ApprovalResult(False, "approval has expired", approver, role)
        nonce = payload.get("nonce", "")
        if nonce in self._used_nonces:
            return ApprovalResult(False, "approval has already been used", approver, role)
        return ApprovalResult(True, "approval verified", approver, role)

    def consume(self, token: str) -> None:
        """Mark a verified token as spent. Call only after the action runs."""
        body = token.split(".", 1)[0]
        payload = json.loads(_unb64(body))
        self._used_nonces.add(payload["nonce"])

    def _sign(self, body: str) -> bytes:
        return hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest()
