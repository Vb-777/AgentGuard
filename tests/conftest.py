import pytest

from agentguard import ApprovalService, AuditLog, ToolGateway, load_policy
from agentguard.demo.dealer import DealerBackend
from agentguard.demo.scenarios import APPROVER_DIRECTORY
from agentguard.report import default_policy_path


class FakeClock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def approvals(clock):
    return ApprovalService(b"test-secret-0123456789abcdef", APPROVER_DIRECTORY, clock=clock)


@pytest.fixture
def backend():
    return DealerBackend()


@pytest.fixture
def gateway(approvals, backend, clock):
    return ToolGateway(load_policy(default_policy_path()), backend.tools(), approvals, AuditLog(clock=clock))
