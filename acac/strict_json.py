"""Strict JSON and primitive utilities for the offline ACAC boundary."""

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, localcontext
import calendar
import hashlib
import json
from pathlib import Path
import re

INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
_INTEGER_TOKEN = re.compile(r"(?:0|[1-9][0-9]*|-[1-9][0-9]*)\Z")
_RFC3339 = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z")


class JSONContractError(ValueError):
    pass


class JSONInteger(int):
    def __new__(cls, value, token):
        instance = int.__new__(cls, value)
        instance.token = token
        return instance


class JSONDecimal(Decimal):
    def __new__(cls, token):
        instance = Decimal.__new__(cls, token)
        instance.token = token
        return instance


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise JSONContractError(f"duplicate_json_member:{key}")
        result[key] = value
    return result


def _constant(value):
    raise JSONContractError(f"non_json_constant:{value}")


def validate_integer_token(token):
    if not isinstance(token, str) or _INTEGER_TOKEN.fullmatch(token) is None:
        raise JSONContractError("noncanonical_integer")
    value = int(token, 10)
    if value < INT64_MIN or value > INT64_MAX:
        raise JSONContractError("integer_out_of_range")
    return value


def _parse_integer(token):
    return JSONInteger(validate_integer_token(token), token)


def _parse_decimal(token):
    return JSONDecimal(token)


def _reject_nulls(value):
    if value is None:
        raise JSONContractError("json_null_forbidden")
    if isinstance(value, dict):
        for child in value.values():
            _reject_nulls(child)
    elif isinstance(value, list):
        for child in value:
            _reject_nulls(child)


def loads(raw):
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise JSONContractError("invalid_utf8") from exc
    if not isinstance(raw, str):
        raise JSONContractError("response_must_be_text_or_utf8_bytes")
    try:
        value = json.loads(raw, object_pairs_hook=_object, parse_float=_parse_decimal,
                           parse_int=_parse_integer, parse_constant=_constant)
        _reject_nulls(value)
        return value
    except (JSONContractError, ValueError, RecursionError) as exc:
        if isinstance(exc, JSONContractError):
            raise
        raise JSONContractError(str(exc)) from exc


def loads_bytes(raw):
    if not isinstance(raw, bytes):
        raise JSONContractError("response_must_be_utf8_bytes")
    return loads(raw)


def loads_legacy(raw):
    """Parse legacy pilot artifacts without applying the v1 null prohibition.

    This is intentionally separate from :func:`loads`; v1 inputs must use the
    strict loader above, while the historical pilot format contains nullable
    diagnostic fields.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="strict")
    if not isinstance(raw, str):
        raise JSONContractError("response_must_be_text_or_utf8_bytes")
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except (JSONContractError, ValueError, RecursionError) as exc:
        if isinstance(exc, JSONContractError):
            raise
        raise JSONContractError(str(exc)) from exc


def read_exact_bytes(path):
    return Path(path).read_bytes()


def sha256_bytes(raw):
    if not isinstance(raw, bytes):
        raise TypeError("sha256_input_must_be_bytes")
    return hashlib.sha256(raw).hexdigest()


def hash_file(path):
    return sha256_bytes(read_exact_bytes(path))


@dataclass(frozen=True)
class ParsedTimestamp:
    original: str
    # Exact UTC seconds from the Unix epoch. Decimal preserves arbitrary
    # RFC 3339 fractional precision beyond datetime's microsecond limit.
    instant: Decimal


def parse_rfc3339_timestamp(value):
    if not isinstance(value, str):
        raise JSONContractError("timestamp_must_be_string")
    if _RFC3339.fullmatch(value) is None:
        raise JSONContractError("invalid_rfc3339_timestamp")
    if value[17:19] == "60":
        raise JSONContractError("leap_second_forbidden")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        # Validate the calendar date, clock, and offset with datetime after
        # removing the fraction (which datetime would otherwise truncate).
        date_part, zone_part = normalized[:-6], normalized[-6:]
        fraction = "0"
        if "." in date_part:
            date_part, fraction_digits = date_part.split(".", 1)
            fraction = "0." + fraction_digits
        instant = datetime.fromisoformat(date_part + zone_part)
    except ValueError as exc:
        raise JSONContractError("invalid_rfc3339_timestamp") from exc
    if instant.tzinfo is None:
        raise JSONContractError("timestamp_requires_explicit_offset")
    utc = instant.astimezone(timezone.utc)
    epoch_integer = calendar.timegm(utc.timetuple())
    # Decimal's default precision is finite.  Use a context sized to the
    # complete fraction and epoch integer so no valid input can be rounded.
    with localcontext() as context:
        context.prec = max(28, len(fraction) + len(str(abs(epoch_integer))) + 2)
        epoch_seconds = Decimal(epoch_integer) + Decimal(fraction)
    # The offset conversion can move the date across a second boundary; the
    # integer epoch calculation above is exact for the validated datetime.
    return ParsedTimestamp(value, epoch_seconds)


def compare_timestamps(left, right):
    a = left if isinstance(left, ParsedTimestamp) else parse_rfc3339_timestamp(left)
    b = right if isinstance(right, ParsedTimestamp) else parse_rfc3339_timestamp(right)
    return (a.instant > b.instant) - (a.instant < b.instant)


def is_integer(value):
    if isinstance(value, JSONInteger):
        return True
    if isinstance(value, JSONDecimal):
        return False
    return ((type(value) is int) or
            (isinstance(value, Decimal) and value.is_finite()
             and value == value.to_integral_value()))


def matches_type(value, declared):
    return {"string": lambda: type(value) is str,
            "boolean": lambda: type(value) is bool,
            "integer": lambda: is_integer(value)}.get(declared, lambda: False)()


def typed(value):
    """Hashable scalar; booleans cannot alias integers. Decimal is exact."""
    if type(value) is bool:
        return ("boolean", value)
    if type(value) is str:
        return ("string", value)
    if is_integer(value):
        return ("integer", int(value))
    raise ValueError("not_a_contract_scalar")


def equal(a, b):
    return typed(a) == typed(b)


def json_ready(value):
    """Serialization only, after validation; preserves integer mathematical values."""
    if isinstance(value, Decimal):
        if not is_integer(value):
            raise ValueError("cannot_serialize_nonintegral_decimal")
        return int(value)
    if isinstance(value, dict):
        return {k: json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(v) for v in value]
    return value


def dumps(value):
    return json.dumps(json_ready(value), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
