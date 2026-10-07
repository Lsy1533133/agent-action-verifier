"""openai_agents_adapter.py — PHM deterministic verifier <-> openai-agents tool input guardrails.

Public glue only. Rule internals remain closed: any verifier object exposing
`verify(plan, [action]) -> {"verdict": "PASS"|"INTERCEPT", "rule": str|None, ...}`
can be plugged in (duck-typed, dependency injection).

Real-world integration (verified against openai-agents SDK source, 2026-10-07):
    from agents.tool_guardrails import tool_input_guardrail, ToolGuardrailFunctionOutput
    from agents.tool_context import ToolContext   # exposes .tool_name, .tool_arguments (JSON str)

    guardrail = phm_tool_input_guardrail(verifier=..., declared_plan=[...])
    agent = Agent(name="x", tools=[...], tool_input_guardrails=[guardrail])
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, List, Mapping, Optional

# ---- make the local verifier importable when run from this directory ----
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    from agents.tool_guardrails import (  # type: ignore
        ToolGuardrailFunctionOutput,
        tool_input_guardrail,
    )
    SDK_AVAILABLE = True
except ImportError:  # closed-loop shape testing without the SDK installed
    SDK_AVAILABLE = False

    class ToolGuardrailFunctionOutput:  # minimal stand-in with identical factory surface
        def __init__(self, output_info=None, behavior=None):
            self.output_info = output_info
            self.behavior = behavior or {"type": "allow"}

        @classmethod
        def allow(cls, output_info=None):
            return cls(output_info=output_info, behavior={"type": "allow"})

        @classmethod
        def reject_content(cls, message, output_info=None):
            return cls(output_info=output_info, behavior={"type": "reject_content", "message": message})

        @classmethod
        def raise_exception(cls, output_info=None):
            return cls(output_info=output_info, behavior={"type": "raise_exception"})

    def tool_input_guardrail(func=None, *, name=None):  # decorator stand-in
        func._guardrail_name = name or func.__name__
        return func


DEFAULT_PLAN = [
    # (op, resource) exact authorizations; resource='*' = explicit wildcard for op
    ("search", "*"), ("calculator", "*"), ("summarize", "*"),
]

# Map common egress-ish argument keys to network resources for R2 domain checks
_NET_KEYS = ("url", "endpoint", "host", "api_url", "base_url")


class Action:
    """Lightweight action record — DATA CONTAINER ONLY (no rule logic; the
    closed verifier reads op/resource/payload_fp off it). Duck-type compatible
    with any verifier that expects these attributes."""
    __slots__ = ("op", "resource", "payload_fp", "planned", "tags")

    def __init__(self, op, resource, payload_fp="", planned=False, tags=()):
        self.op = op
        self.resource = resource
        self.payload_fp = payload_fp
        self.planned = planned
        self.tags = set(tags)


def _pending_action_from(tool_name: str, tool_arguments: str) -> Any:
    """Build a verifier Action from the SDK's tool context fields."""
    resource = tool_name
    args: Mapping[str, Any] = {}
    try:
        parsed = json.loads(tool_arguments) if tool_arguments else {}
        if isinstance(parsed, dict):
            args = parsed
    except (json.JSONDecodeError, TypeError):
        args = {}

    for key in _NET_KEYS:
        v = str(args.get(key, ""))
        if v:
            # normalize egress args to domain-level net:// resource:
            # plan authorization & R2 domain checks are domain-granular
            host = v.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            resource = f"net://{host}"
            break
    else:
        for key in ("path", "file", "target", "resource"):
            v = str(args.get(key, ""))
            if v:
                resource = v
                break

    fp = str(args.get("content_hash", args.get("payload_fp", "")))[:64]
    # Action class follows the FACTUAL SHAPE of arguments, not the tool's name:
    # egress-ish arg present -> op='fetch' (OP_NET member) so R2 domain checks apply
    op = "fetch" if resource.startswith("net://") else tool_name
    return Action(op=op, resource=resource, payload_fp=fp, planned=False)


def phm_tool_input_guardrail(
    verifier: Any,
    declared_plan: Optional[List[Any]] = None,
    on_veto: str = "reject_content",  # "reject_content" | "raise_exception"
    name: str = "phm_deterministic_verifier",
):
    """Create a deterministic tool-input guardrail from a PHM verifier object.

    verifier      : object with .verify(plan, [action]) -> dict (rule internals closed)
    declared_plan : list of (op, resource) tuples; falls back to a permissive default
    on_veto       : how a VETO surfaces ("reject_content" keeps the run alive and
                    feeds the veto reason to the model; "raise_exception" halts hard)
    """
    plan = declared_plan or DEFAULT_PLAN

    def _to_action(a):
        if isinstance(a, Action):
            return a
        if hasattr(a, "op"):          # duck-typed action objects (DemoAction, ...)
            return Action(op=a.op, resource=a.resource, planned=True)
        return Action(op=a[0], resource=a[1], planned=True)  # (op, resource) tuples

    plan_actions = [_to_action(a) for a in plan]

    def _guard(data: Any) -> ToolGuardrailFunctionOutput:
        tool_name = getattr(data.context, "tool_name", "") or "unknown_tool"
        tool_args = getattr(data.context, "tool_arguments", "") or "{}"
        pending = _pending_action_from(tool_name, tool_args)
        result = verifier.verify(plan_actions, [pending])

        if result.get("verdict") == "PASS":
            return ToolGuardrailFunctionOutput.allow(output_info={"phm": result})

        info = {"phm": result, "tool": tool_name}
        message = f"[PHM veto] rule {result.get('rule')}: {result.get('evidence')}"
        if on_veto == "raise_exception":
            return ToolGuardrailFunctionOutput.raise_exception(output_info=info)
        return ToolGuardrailFunctionOutput.reject_content(message, output_info=info)

    _guard.__name__ = name
    if SDK_AVAILABLE:
        return tool_input_guardrail(_guard, name=name)
    return tool_input_guardrail(_guard)  # decorator stand-in marks the function
