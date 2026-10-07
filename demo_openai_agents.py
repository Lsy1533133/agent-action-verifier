"""demo_openai_agents.py — 5-minute demo: deterministic plan-execution veto inside a real agent loop.

What you will see when you run this:
  [CASE benign]   LLM calls web_query(whitelisted url) -> guardrail ALLOW  -> tool body EXECUTES
  [CASE breach]   LLM calls web_query(other url)       -> guardrail VETO  -> ToolInputGuardrailTripwireTriggered
                                                                    -> tool body NEVER runs (zero side effects)

Requirements:
  pip install openai-agents          (tested on 0.23.1)
  export OPENAI_API_KEY=sk-...       (or edit BASE_URL/MODEL below for an OpenAI-compatible endpoint)

Run:
  python3 demo_openai_agents.py

This demo uses the same three-part shape as the adapter in this repo:
  declared plan (fact-shaped)  ->  deterministic verifier  ->  SDK guardrail behavior
"""
import asyncio
import json
import os

BASE_URL = os.environ.get("PHM_BASE_URL", "https://api.openai.com/v1")
MODEL = os.environ.get("PHM_MODEL", "gpt-4o-mini")
API_KEY = os.environ.get("OPENAI_API_KEY", "")

from agents import Agent, Runner, function_tool, set_default_openai_client, set_tracing_disabled
from agents.exceptions import ToolInputGuardrailTripwireTriggered
from openai import AsyncOpenAI

from openai_agents_adapter import phm_tool_input_guardrail


# ---------------------------------------------------------------------------
# DemoVerifier — a MINIMAL stand-in so this demo is self-contained.
# It only implements the two rules the demo exercises (out-of-plan + egress
# whitelist) with the same verify() shape the adapter expects.
# The production verifier (7 rule families, sequence differential, audit chains)
# is closed-source — swap it in via the same duck-typed interface.
# ---------------------------------------------------------------------------
class DemoVerifier:
    def __init__(self, whitelist_domains):
        self.wl = set(whitelist_domains)

    def verify(self, plan, actual):
        plan_ops = {a.op for a in plan}
        plan_res = {(a.op, a.resource) for a in plan}
        for i, act in enumerate(actual):
            if (act.op, act.resource) not in plan_res and act.op not in plan_ops:
                return {"verdict": "INTERCEPT", "rule": "R1", "at": i,
                        "evidence": {"op": act.op, "resource": act.resource}}
            if act.resource.startswith("net://"):
                dom = act.resource[6:].split("/")[0]
                if dom not in self.wl:
                    return {"verdict": "INTERCEPT", "rule": "R2", "at": i,
                            "evidence": {"domain": dom}}
        return {"verdict": "PASS", "rule": None, "at": None, "evidence": {}}


class DemoAction:
    __slots__ = ("op", "resource")
    def __init__(self, op, resource):
        self.op = op
        self.resource = resource


# 1) Declared plan — fact-shaped: "fetch is allowed ONLY to this corpus host"
VERIFIER = DemoVerifier(whitelist_domains=("api.example-corpus.local",))
PLAN = [
    DemoAction(op="fetch", resource="net://api.example-corpus.local"),
    DemoAction(op="calculator", resource="*"),
]
GUARDRAIL = phm_tool_input_guardrail(
    verifier=VERIFIER, declared_plan=PLAN, on_veto="raise_exception"
)

TOOL_LOG = []

# 2) SDK seam — guardrail attached at tool definition (openai-agents >= 0.23)
@function_tool(tool_input_guardrails=[GUARDRAIL])
def web_query(url: str, query: str) -> str:
    """Query a web endpoint and return the result."""
    TOOL_LOG.append(url)  # side effect — proves the body ran
    return f"[result for {query}]"

AGENT = Agent(
    name="demo",
    model=MODEL,
    instructions="Data retrieval assistant. Call web_query with exactly the url and query the user gives.",
    tools=[web_query],
)


async def case(label: str, url: str):
    TOOL_LOG.clear()
    try:
        await Runner.run(AGENT, f"url={url} query=grid data")
        print(f"[{label}] run completed          | tool body executed: {bool(TOOL_LOG)} ({TOOL_LOG})")
    except ToolInputGuardrailTripwireTriggered as e:
        info = getattr(getattr(e, "guardrail_result", None), "output", None)
        print(f"[{label}] VETOED pre-execution | tool body executed: {bool(TOOL_LOG)} | info: {str(getattr(info, 'output_info', None))[:120]}")


async def main():
    if not API_KEY:
        print("Set OPENAI_API_KEY (and optionally PHM_BASE_URL / PHM_MODEL) first.")
        return
    set_default_openai_client(AsyncOpenAI(base_url=BASE_URL, api_key=API_KEY))
    set_tracing_disabled(True)

    await case("benign", "https://api.example-corpus.local/v1")
    await case("breach", "https://collector.internal.example.net/api")


if __name__ == "__main__":
    asyncio.run(main())
