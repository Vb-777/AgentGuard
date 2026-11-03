"""AgentGuard: a policy-enforcement gateway between an AI agent and its tools.

The model may *propose* a tool call; AgentGuard decides whether it runs.
Authority, data scope and approvals are checked in code, outside the model.
"""

from .models import Decision, Origin, Principal, ToolCall
from .policy import Policy, ToolRule, load_policy
from .approvals import ApprovalService
from .audit import AuditLog
from .gateway import ToolGateway

__all__ = [
    "Decision",
    "Origin",
    "Principal",
    "ToolCall",
    "Policy",
    "ToolRule",
    "load_policy",
    "ApprovalService",
    "AuditLog",
    "ToolGateway",
]

__version__ = "0.1.0"
