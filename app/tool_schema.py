"""
Phase 7 — lightweight tool-argument JSON-schema validator.

Avoids pulling in the full ``jsonschema`` dependency for what is a tiny,
fixed set of tool schemas. Handles the constructs used by the tool
definitions in :func:`agent._build_tool_definitions`:

* ``type: object`` with ``properties`` and ``required``
* ``type: string`` with optional ``enum`` and ``maxLength``
* ``type: integer`` / ``number`` / ``boolean`` / ``array``

Validation errors raise :class:`ToolArgumentError` with a precise dotted
path so the audit event records exactly which field failed.
"""

from __future__ import annotations

from typing import Any

_PY_TYPES: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    # In JSON, ``42`` is integer/number; in Python ``True/False`` is also
    # ``int``, so reject bools explicitly when type=="integer".
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
}


class ToolArgumentError(ValueError):
    """Raised when tool arguments do not match the declared JSON schema."""

    def __init__(self, message: str, *, path: str = "") -> None:
        self.path = path
        super().__init__(f"{path or '<root>'}: {message}")


def validate_tool_arguments(args: Any, schema: dict[str, Any]) -> None:
    """Validate *args* against an OpenAI-style function ``parameters`` schema.

    ``schema`` is the inner ``parameters`` object (not the wrapping function
    definition). Raises :class:`ToolArgumentError` on the first violation.
    """
    if not isinstance(schema, dict):
        # Schema-less tools accept anything.
        return
    _validate_node(args, schema, path="")


def _validate_node(value: Any, schema: dict[str, Any], *, path: str) -> None:
    if not isinstance(schema, dict):
        return
    declared = schema.get("type")
    if declared:
        py_type = _PY_TYPES.get(declared)
        if py_type is None:
            return  # Unknown type — be permissive rather than break.
        if declared == "integer" and isinstance(value, bool):
            raise ToolArgumentError(
                "expected integer, got bool", path=path
            )
        if declared == "number" and isinstance(value, bool):
            raise ToolArgumentError(
                "expected number, got bool", path=path
            )
        if not isinstance(value, py_type):
            raise ToolArgumentError(
                f"expected {declared}, got {type(value).__name__}", path=path
            )

    # ── object ───────────────────────────────────────────────────────────
    if declared == "object" or "properties" in schema:
        if not isinstance(value, dict):
            raise ToolArgumentError("expected object", path=path)
        required = schema.get("required") or []
        for req in required:
            if req not in value:
                raise ToolArgumentError(
                    f"missing required property {req!r}", path=path
                )
        properties = schema.get("properties") or {}
        additional = schema.get("additionalProperties", True)
        for key, child_value in value.items():
            child_path = f"{path}.{key}" if path else key
            child_schema = properties.get(key)
            if child_schema is None:
                if additional is False:
                    raise ToolArgumentError(
                        f"unexpected property {key!r}", path=child_path
                    )
                continue
            _validate_node(child_value, child_schema, path=child_path)

    # ── string ───────────────────────────────────────────────────────────
    if declared == "string":
        max_len = schema.get("maxLength")
        if isinstance(max_len, int) and len(value) > max_len:
            raise ToolArgumentError(
                f"string longer than maxLength={max_len}", path=path
            )
        enum_values = schema.get("enum")
        if enum_values is not None and value not in enum_values:
            raise ToolArgumentError(
                f"value {value!r} not in enum {enum_values}", path=path
            )

    # ── array ────────────────────────────────────────────────────────────
    if declared == "array":
        items_schema = schema.get("items")
        if isinstance(items_schema, dict):
            for idx, item in enumerate(value):
                _validate_node(item, items_schema, path=f"{path}[{idx}]")
        max_items = schema.get("maxItems")
        if isinstance(max_items, int) and len(value) > max_items:
            raise ToolArgumentError(
                f"array longer than maxItems={max_items}", path=path
            )


__all__ = ["ToolArgumentError", "validate_tool_arguments"]
