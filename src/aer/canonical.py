"""Canonical JSON for hashing and signing.

Implements the JSON Canonicalization Scheme (RFC 8785) restricted to the
value types AER permits: objects, arrays, strings, integers, booleans and
null. Floating-point numbers are rejected, which removes the only part of
RFC 8785 that is hard to implement identically across languages.
"""

from __future__ import annotations

import json
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalizationError(ValueError):
    """The value cannot be represented in AER canonical form."""


def _string(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("string contains a lone surrogate") from exc
    # json.dumps with ensure_ascii=False escapes exactly what RFC 8785 requires:
    # the quote, the backslash, and U+0000 to U+001F (short forms where defined,
    # lowercase \u00xx otherwise). Everything else is emitted as is.
    return json.dumps(value, ensure_ascii=False)


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError("integer outside the range -(2^53-1) to 2^53-1")
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError("floating-point numbers are not permitted")
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
        # RFC 8785 orders members by the UTF-16 code units of their names.
        ordered = sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_string(k) + ":" + _serialize(value[k]) for k in ordered) + "}"
    raise CanonicalizationError(f"unsupported type: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return the canonical UTF-8 encoding of a JSON value."""
    return _serialize(value).encode("utf-8")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate object member: {key!r}")
        result[key] = value
    return result


def _reject_float(text: str) -> Any:
    raise CanonicalizationError(f"floating-point number not permitted: {text}")


def strict_loads(text: str) -> Any:
    """Parse JSON, rejecting duplicate members, floats, NaN and Infinity."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(f"invalid JSON: {exc.msg}") from exc
