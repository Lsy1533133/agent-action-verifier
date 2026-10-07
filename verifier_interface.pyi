"""verifier_interface.pyi — public contract of the deterministic action verifier.

Integration shape: wrap the agent's action-dispatch point. The verifier receives
the declared plan and the pending action, and returns a verdict BEFORE the
action is executed. Decision path is fixed-constant math: no LLM call, no
learned parameters, no network access.

Rule families (ids are stable; internals closed):
  R1  out-of-plan action     : action not covered by the declared plan set
  R2  network egress breach  : destination outside allowlist (host/port/proto)
  R3  scope escalation       : action exceeds declared role/credential scope
  R4  tool-consent violation : tool invoked without matching declared consent
  R5  dangerous value class  : parameter falls into a pre-declared danger class
  R6  division/zero guard    : arithmetic-unsafe parameter combination
  R7  uninitialised state    : action consumes state that was never initialised
"""

from typing import Any, Mapping, Sequence
from typing_extensions import Literal, Protocol

Verdict = Literal["PASS", "VETO"]


class AuditResult(Protocol):
    verdict: Verdict          # "PASS" -> execute; "VETO" -> block before side effects
    rule_id: str              # "" for PASS; "R1".."R7" (+optional suffix) for VETO
    reason: str               # human-readable, stable wording
    latency_ms: float         # decision cost, microsecond-scale


class ActionVerifier(Protocol):
    def audit(
        self,
        declared_plan: Mapping[str, Sequence[str]],  # planned tools / scopes / egress
        pending_action: Mapping[str, Any],           # the action about to execute
    ) -> AuditResult: ...

# Warranty: deterministic, seeded, reproducible. Same inputs -> same verdict.
# This interface carries no implementation; internals remain closed by design.
