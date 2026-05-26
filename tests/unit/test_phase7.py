"""Tests for Phase 7 — additional OWASP/agentic guardrails.

Covers:
* Pricing table + fallback (LLM04)
* CostBudget consume + breach
* Loop detection (LLM Excessive Agency adjacent)
* Output sanitization (LLM02 — Insecure Output Handling)
* Tool argument schema validation
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[2] / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from errors import CostBudgetExceededError, LoopDetectedError  # noqa: E402
from loop_detection import LoopDetector  # noqa: E402
from output_handlers import (  # noqa: E402
    sanitize_agent_result,
    sanitize_for_csv,
    sanitize_for_html,
    sanitize_for_json,
)
from pricing import _FALLBACK, estimate_cost, get_price  # noqa: E402
from rate_limiter import CostBudget  # noqa: E402
from tool_schema import ToolArgumentError, validate_tool_arguments  # noqa: E402


# ── Pricing ──────────────────────────────────────────────────────────────────
class TestPricing:
    def test_known_model_returns_table_price(self):
        price = get_price("gpt-4o")
        assert price.prompt_per_1k == 0.0050
        assert price.completion_per_1k == 0.0150

    def test_unknown_model_returns_fallback(self):
        price = get_price("does-not-exist")
        assert price == _FALLBACK

    def test_empty_model_returns_fallback(self):
        assert get_price("") == _FALLBACK

    def test_dated_model_suffix_strips_to_base(self):
        # "gpt-4o-2024-08-06" should map to the "gpt-4o" base.
        price = get_price("gpt-4o-2024-08-06")
        assert price.prompt_per_1k == 0.0050

    def test_estimate_cost_basic(self):
        # 1000 prompt + 1000 completion at gpt-4o = 0.005 + 0.015 = 0.020
        cost = estimate_cost(
            model_name="gpt-4o", prompt_tokens=1000, completion_tokens=1000
        )
        assert cost == pytest.approx(0.020)

    def test_estimate_cost_clamps_negative(self):
        cost = estimate_cost(
            model_name="gpt-4o", prompt_tokens=-50, completion_tokens=-50
        )
        assert cost == 0.0

    def test_estimate_cost_unknown_model_uses_conservative_fallback(self):
        cost = estimate_cost(
            model_name="unknown-x", prompt_tokens=1000, completion_tokens=0
        )
        # Fallback prompt price is the most expensive (gpt-5).
        assert cost == pytest.approx(0.0125)


# ── CostBudget ───────────────────────────────────────────────────────────────
class TestCostBudget:
    def test_consume_accumulates(self):
        budget = CostBudget(max_usd=1.00)
        total = budget.consume(
            model_name="gpt-4o", prompt_tokens=1000, completion_tokens=0
        )
        assert total == pytest.approx(0.005)
        total = budget.consume(
            model_name="gpt-4o", prompt_tokens=1000, completion_tokens=0
        )
        assert total == pytest.approx(0.010)
        assert budget.used_usd == pytest.approx(0.010)

    def test_breach_raises(self):
        budget = CostBudget(max_usd=0.01)
        # 2000 prompt @ gpt-4o = 0.010 — at the ceiling, allowed.
        budget.consume(
            model_name="gpt-4o", prompt_tokens=2000, completion_tokens=0
        )
        with pytest.raises(CostBudgetExceededError) as ei:
            budget.consume(
                model_name="gpt-4o", prompt_tokens=1, completion_tokens=0
            )
        assert ei.value.budget_usd == 0.01
        assert ei.value.estimated_cost_usd > 0.01

    def test_invalid_max_rejected(self):
        with pytest.raises(ValueError):
            CostBudget(max_usd=0)
        with pytest.raises(ValueError):
            CostBudget(max_usd=-1)


# ── Loop detection ───────────────────────────────────────────────────────────
class TestLoopDetector:
    def test_distinct_calls_never_trip(self):
        ld = LoopDetector(max_depth=3)
        for i in range(10):
            ld.observe("file_read", {"path": f"/p/{i}"})

    def test_repeat_below_threshold_passes(self):
        ld = LoopDetector(max_depth=3)
        ld.observe("file_read", {"path": "/p"})
        ld.observe("file_read", {"path": "/p"})  # 2nd occurrence, threshold=3

    def test_repeat_at_threshold_raises(self):
        ld = LoopDetector(max_depth=3)
        ld.observe("file_read", {"path": "/p"})
        ld.observe("file_read", {"path": "/p"})
        with pytest.raises(LoopDetectedError) as ei:
            ld.observe("file_read", {"path": "/p"})
        assert ei.value.tool_name == "file_read"
        assert ei.value.repetitions >= 3

    def test_arg_order_insensitive(self):
        ld = LoopDetector(max_depth=2)
        ld.observe("http_get", {"a": 1, "b": 2})
        with pytest.raises(LoopDetectedError):
            ld.observe("http_get", {"b": 2, "a": 1})

    def test_window_expires_old_keys(self):
        # Threshold=3, window=3: an old call falls out before it can trip.
        ld = LoopDetector(max_depth=3, window=3)
        ld.observe("file_read", {"path": "/p"})
        ld.observe("other", {"q": 1})
        ld.observe("other", {"q": 2})
        ld.observe("other", {"q": 3})
        # First "/p" call has rolled off the window — this should not raise.
        ld.observe("file_read", {"path": "/p"})

    def test_invalid_threshold_rejected(self):
        with pytest.raises(ValueError):
            LoopDetector(max_depth=1)

    def test_non_json_serializable_args_still_work(self):
        # repr fallback path — should not raise.
        class Obj:
            pass

        ld = LoopDetector(max_depth=2)
        ld.observe("t", Obj())
        # Two distinct instances → different repr → not a loop.
        ld.observe("t", Obj())


# ── Output sanitization ──────────────────────────────────────────────────────
class TestSanitizeForCsv:
    @pytest.mark.parametrize(
        "lead", ["=", "+", "-", "@", "|"]
    )
    def test_formula_leads_are_prefixed(self, lead):
        assert sanitize_for_csv(lead + "cmd").startswith("'")

    def test_excel_dde_classic(self):
        # Real-world payload that pops calc.exe in legacy Excel.
        sanitized = sanitize_for_csv("=cmd|' /C calc'!A0")
        assert sanitized.startswith("'=")

    def test_internal_chars_untouched(self):
        assert sanitize_for_csv("hello = world") == "hello = world"

    def test_empty_input(self):
        assert sanitize_for_csv("") == ""
        assert sanitize_for_csv(None) == ""


class TestSanitizeForHtml:
    def test_escapes_angle_brackets(self):
        out = sanitize_for_html("<script>alert(1)</script>")
        assert "<" not in out
        assert "&lt;" in out

    def test_escapes_quotes(self):
        out = sanitize_for_html('"x" & y')
        assert "&quot;" in out
        assert "&amp;" in out

    def test_none_returns_empty(self):
        assert sanitize_for_html(None) == ""


class TestSanitizeForJson:
    def test_round_trip(self):
        out = sanitize_for_json({"b": 1, "a": 2})
        # Deterministic key order + no whitespace.
        assert out == '{"a":2,"b":1}'

    def test_ensure_ascii(self):
        out = sanitize_for_json({"k": "\u202eRTL"})
        # RTL-override character escaped to ASCII.
        assert "\\u202e" in out

    def test_unknown_type_degrades_to_str(self):
        class Obj:
            def __str__(self):
                return "Obj-rep"

        out = sanitize_for_json({"k": Obj()})
        assert "Obj-rep" in out


class TestSanitizeAgentResult:
    def test_only_output_field_is_escaped(self):
        result = {"output": "<b>x</b>", "tokens_used": 5}
        sanitize_agent_result(result)
        assert "<b>" not in result["output"]
        assert result["tokens_used"] == 5

    def test_non_dict_passthrough(self):
        assert sanitize_agent_result("hi") == "hi"
        assert sanitize_agent_result(None) is None


# ── Tool argument schema validation ──────────────────────────────────────────
_FILE_WRITE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "maxLength": 200},
        "content": {"type": "string"},
        "content_type": {
            "type": "string",
            "enum": ["text/plain", "application/json"],
        },
    },
    "required": ["path", "content"],
}


class TestValidateToolArguments:
    def test_happy_path(self):
        validate_tool_arguments(
            {"path": "/p", "content": "hello", "content_type": "text/plain"},
            _FILE_WRITE_SCHEMA,
        )

    def test_missing_required(self):
        with pytest.raises(ToolArgumentError, match="missing required"):
            validate_tool_arguments({"path": "/p"}, _FILE_WRITE_SCHEMA)

    def test_wrong_type(self):
        with pytest.raises(ToolArgumentError, match="expected string"):
            validate_tool_arguments(
                {"path": 123, "content": "x"}, _FILE_WRITE_SCHEMA
            )

    def test_bool_rejected_for_integer(self):
        schema = {"type": "object", "properties": {"n": {"type": "integer"}}}
        with pytest.raises(ToolArgumentError, match="expected integer"):
            validate_tool_arguments({"n": True}, schema)

    def test_enum_violation(self):
        with pytest.raises(ToolArgumentError, match="enum"):
            validate_tool_arguments(
                {
                    "path": "/p",
                    "content": "x",
                    "content_type": "text/evil",
                },
                _FILE_WRITE_SCHEMA,
            )

    def test_max_length(self):
        with pytest.raises(ToolArgumentError, match="maxLength"):
            validate_tool_arguments(
                {"path": "x" * 500, "content": "x"}, _FILE_WRITE_SCHEMA
            )

    def test_array_items(self):
        schema = {
            "type": "object",
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}}
            },
        }
        validate_tool_arguments({"tags": ["a", "b"]}, schema)
        with pytest.raises(ToolArgumentError):
            validate_tool_arguments({"tags": ["a", 1]}, schema)

    def test_max_items(self):
        schema = {
            "type": "object",
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 2}
            },
        }
        with pytest.raises(ToolArgumentError, match="maxItems"):
            validate_tool_arguments({"tags": ["a", "b", "c"]}, schema)

    def test_additional_properties_false(self):
        schema = {
            "type": "object",
            "properties": {"x": {"type": "string"}},
            "additionalProperties": False,
        }
        with pytest.raises(ToolArgumentError, match="unexpected"):
            validate_tool_arguments({"x": "y", "z": "extra"}, schema)

    def test_empty_schema_permissive(self):
        # No "type" or "properties" → accept anything.
        validate_tool_arguments({"whatever": 1}, {})

    def test_error_path_reflects_nested_field(self):
        schema = {
            "type": "object",
            "properties": {
                "outer": {
                    "type": "object",
                    "properties": {"inner": {"type": "string"}},
                    "required": ["inner"],
                }
            },
            "required": ["outer"],
        }
        with pytest.raises(ToolArgumentError, match="outer"):
            validate_tool_arguments({"outer": {}}, schema)


# ── agent.py integration: _tool_parameters_schema lookup ────────────────────
class TestAgentToolSchemaLookup:
    def test_returns_schema_for_known_tool(self):
        import agent

        schema = agent._tool_parameters_schema("file_write")
        assert schema is not None
        assert "path" in schema["properties"]
        assert "content" in schema["required"]

    def test_returns_none_for_unknown_tool(self):
        import agent

        assert agent._tool_parameters_schema("mcp::external::weirdo") is None
