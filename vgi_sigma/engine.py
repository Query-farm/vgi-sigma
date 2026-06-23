"""Pure Sigma rule lifecycle + evaluation logic: parse once, evaluate per row.

This module owns everything VGI-independent: parsing a Sigma rule YAML into a
compiled, cached form and evaluating that compiled rule against an event record
(a plain ``dict`` decoded from JSON). It has no Arrow or VGI dependency and is
directly unit-testable.

Why a cache
-----------
VGI keeps the worker process alive across queries, and the headline usage is a
*constant* rule applied across a whole log column::

    WHERE sigma_match(to_json(t), rule)

Parsing + compiling a rule is the expensive part; evaluating a compiled rule
against one event is cheap. So :func:`compile_rule` is wrapped in an
``lru_cache`` keyed by the rule's *text*: the same rule string compiles **once**
and is then evaluated per row.

What we evaluate
----------------
pySigma parses a rule into a ``SigmaRule`` whose ``detection.parsed_condition``
yields a boolean **condition tree** (``ConditionAND`` / ``ConditionOR`` /
``ConditionNOT`` over leaf field/keyword expressions). The selector forms
``1 of selection_*``, ``all of them``, ``all of selection_*``, etc. are expanded
*by pySigma* into that same tree, so we get them for free by walking it. Each
leaf is either:

- ``ConditionFieldEqualsValueExpression`` -- a ``field`` compared to a value, and
- ``ConditionValueExpression`` -- a bare keyword search (no field) matched
  against every string value in the event.

Supported field modifiers (the common Sigma cases):

- plain equality (case-insensitive for strings; numeric/bool compared by value)
- ``contains`` / ``startswith`` / ``endswith`` (case-insensitive substring/affix)
- ``re`` (regular expression, via Python ``re.search``)
- ``all`` (every listed value must match this field, rather than the default OR)
- a list of values means OR (any one matches) -- unless ``all`` is present.
- ``*`` / ``?`` wildcards inside plain/contains/... values (``*`` -> ``.*``,
  ``?`` -> ``.``), the standard Sigma globbing.

Anything outside this set (e.g. ``base64``, ``cidr``, ``lt``/``gt`` numeric
comparison, field references, ``|expand``) raises :class:`UnsupportedRuleError`
during compilation, which the callers turn into a clear error (evaluators) or a
``false`` result (``sigma_check``). This keeps behaviour honest: we never
silently mis-evaluate a modifier we don't implement.

Event contract
--------------
An event is a JSON object whose keys are the field names the rule references
(e.g. ``EventID``, ``LogonType``, ``CommandLine``). Nested objects are addressed
with **dotted** field names (``foo.bar`` -> ``event["foo"]["bar"]``); pySigma
itself uses the same dotted convention. A missing field never matches a
positive comparison. Everything here is total: a NULL/empty event or rule yields
``None`` / no match and never raises out of :func:`evaluate`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)


class SigmaWorkerError(Exception):
    """Base class for errors this worker raises (parse / unsupported)."""


class RuleParseError(SigmaWorkerError):
    """The rule YAML is malformed or not a valid single Sigma rule."""


class UnsupportedRuleError(SigmaWorkerError):
    """The rule uses a modifier / value type this worker does not implement."""


# Modifier class name -> the comparison kind we implement.
_SUPPORTED_AFFIX_MODIFIERS = {
    "SigmaContainsModifier": "contains",
    "SigmaStartswithModifier": "startswith",
    "SigmaEndswithModifier": "endswith",
}
# Modifiers that change *combination* (all-of-list) or value interpretation
# (regex) rather than the affix kind.
_MOD_ALL = "SigmaAllModifier"
_MOD_RE = "SigmaRegularExpressionModifier"


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """A parsed, validated Sigma rule ready to evaluate against events.

    ``rule`` is the pySigma object (metadata source for ``sigma_rule_info``),
    ``condition`` is the root of the boolean condition tree, and ``fields`` is
    the sorted set of event field names the rule references.
    """

    rule: SigmaRule
    condition: Any
    fields: tuple[str, ...]


# ---------------------------------------------------------------------------
# Parsing + compilation (cached by rule text)
# ---------------------------------------------------------------------------


def _parse_rule(rule_yaml: str) -> SigmaRule:
    """Parse a single Sigma rule YAML, raising :class:`RuleParseError`."""
    try:
        rule = SigmaRule.from_yaml(rule_yaml)
    except SigmaError as exc:
        raise RuleParseError(f"invalid Sigma rule: {exc}") from exc
    except Exception as exc:  # malformed YAML, wrong shape, etc.
        raise RuleParseError(f"could not parse rule: {exc}") from exc
    if rule.errors:
        raise RuleParseError(f"invalid Sigma rule: {rule.errors[0]}")
    return rule


def _validate_leaf(node: Any) -> None:
    """Reject leaves that use modifiers / value types we cannot evaluate."""
    if isinstance(node, ConditionFieldEqualsValueExpression):
        value = node.value
        if isinstance(value, (SigmaString, SigmaNumber, SigmaBool, SigmaNull, SigmaRegularExpression)):
            return
        raise UnsupportedRuleError(f"unsupported value type {type(value).__name__} for field '{node.field}'")
    if isinstance(node, ConditionValueExpression):
        if isinstance(node.value, (SigmaString, SigmaNumber, SigmaBool)):
            return
        raise UnsupportedRuleError(f"unsupported keyword value type {type(node.value).__name__}")
    raise UnsupportedRuleError(f"unsupported condition node {type(node).__name__}")


def _validate_modifiers(rule: SigmaRule) -> None:
    """Ensure every detection item uses only modifiers we implement."""
    for det in rule.detection.detections.values():
        for item in _iter_detection_items(det):
            for mod in item.modifiers:
                name = mod.__name__
                if name in _SUPPORTED_AFFIX_MODIFIERS or name in (_MOD_ALL, _MOD_RE):
                    continue
                raise UnsupportedRuleError(
                    f"unsupported field modifier '{name.removeprefix('Sigma').removesuffix('Modifier')}'"
                    f" on field '{item.field}'"
                )


def _iter_detection_items(detection: Any) -> Any:
    """Yield every ``SigmaDetectionItem`` under a detection (recursively)."""
    for item in detection.detection_items:
        if hasattr(item, "detection_items"):  # a nested SigmaDetection
            yield from _iter_detection_items(item)
        else:
            yield item


def _walk_tree(node: Any) -> None:
    """Walk a condition tree, validating every leaf; raise on unsupported."""
    if isinstance(node, (ConditionAND, ConditionOR, ConditionNOT)):
        for arg in node.args:
            _walk_tree(arg)
    else:
        _validate_leaf(node)


@lru_cache(maxsize=256)
def compile_rule(rule_yaml: str) -> CompiledRule:
    """Parse + validate + compile a rule, cached by its text.

    The expensive parse/validate happens once per distinct rule string; the
    returned :class:`CompiledRule` is evaluated per event. Raises
    :class:`RuleParseError` for malformed YAML and :class:`UnsupportedRuleError`
    for modifiers/value types outside the supported set.
    """
    rule = _parse_rule(rule_yaml)
    _validate_modifiers(rule)
    parsed = rule.detection.parsed_condition
    if not parsed:
        raise RuleParseError("rule has no detection condition")
    condition = parsed[0].parse()
    _walk_tree(condition)
    fields = tuple(sorted(_referenced_fields(rule)))
    return CompiledRule(rule=rule, condition=condition, fields=fields)


def _referenced_fields(rule: SigmaRule) -> set[str]:
    """Distinct event field names the rule's detections reference."""
    fields: set[str] = set()
    for det in rule.detection.detections.values():
        for item in _iter_detection_items(det):
            if item.field:
                fields.add(item.field)
    return fields


# ---------------------------------------------------------------------------
# Value matching
# ---------------------------------------------------------------------------


def _wildcard_to_regex(sigma_str: SigmaString, *, anchored: str) -> re.Pattern[str]:
    """Compile a SigmaString (literal + ``*``/``?`` wildcards) to a regex.

    ``anchored`` controls the affix: ``"full"`` anchors both ends (plain
    equality), ``"prefix"`` anchors the start (startswith), ``"suffix"`` anchors
    the end (endswith), ``"none"`` anchors neither (contains). Matching is
    case-insensitive, the Sigma default for unmodified string comparisons.
    """
    parts: list[str] = []
    for piece in sigma_str.s:
        if piece == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif piece == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(piece, str):
            parts.append(re.escape(piece))
        else:  # placeholder fragment (only via |expand, which we reject earlier)
            parts.append(re.escape(str(piece)))
    body = "".join(parts)
    prefix = "" if anchored in ("none", "suffix") else "^"
    suffix = "" if anchored in ("none", "prefix") else "$"
    return re.compile(prefix + body + suffix, re.IGNORECASE | re.DOTALL)


def _coerce_event_str(value: Any) -> str:
    """Render an event value as a string for substring/regex matching."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _match_string_value(event_value: Any, sigma_str: SigmaString, kind: str) -> bool:
    """Match one event value against one SigmaString under a comparison kind."""
    if event_value is None:
        return False
    text = _coerce_event_str(event_value)
    if kind == "plain" and not sigma_str.contains_special():
        # Fast, exact, case-insensitive equality for plain literals.
        return text.casefold() == sigma_str.to_plain().casefold()
    anchored = {
        "plain": "full",
        "contains": "none",
        "startswith": "prefix",
        "endswith": "suffix",
    }[kind]
    return _wildcard_to_regex(sigma_str, anchored=anchored).search(text) is not None


def _match_regex_value(event_value: Any, sigma_re: SigmaRegularExpression) -> bool:
    """Match one event value against a Sigma ``|re`` regular expression."""
    if event_value is None:
        return False
    try:
        pattern = re.compile(sigma_re.regexp.to_plain())
    except re.error:
        return False
    return pattern.search(_coerce_event_str(event_value)) is not None


def _match_scalar_value(event_value: Any, sigma_value: Any, kind: str) -> bool:
    """Match one event value against one Sigma value (any supported type)."""
    if isinstance(sigma_value, SigmaRegularExpression):
        return _match_regex_value(event_value, sigma_value)
    if isinstance(sigma_value, SigmaNull):
        return event_value is None
    if isinstance(sigma_value, SigmaBool):
        if isinstance(event_value, bool):
            return event_value is sigma_value.boolean
        return _coerce_event_str(event_value).casefold() == str(sigma_value.boolean).casefold()
    if isinstance(sigma_value, SigmaNumber):
        if isinstance(event_value, bool):
            return False
        if isinstance(event_value, (int, float)):
            return float(event_value) == float(sigma_value.number)
        # Number-as-string in the event (JSON often stringifies): compare text.
        return _coerce_event_str(event_value) == str(sigma_value.to_plain())
    if isinstance(sigma_value, SigmaString):
        return _match_string_value(event_value, sigma_value, kind)
    return False


def _event_values(event_value: Any) -> list[Any]:
    """Flatten an event value into the scalars to compare (lists -> elements)."""
    if isinstance(event_value, list):
        return event_value
    return [event_value]


def _lookup_field(event: dict[str, Any], field: str) -> tuple[bool, Any]:
    """Resolve a (possibly dotted) field name in the event.

    Returns ``(present, value)``. Supports both a literal dotted key and nested
    object traversal (``a.b`` -> ``event["a"]["b"]``), preferring a literal key
    if one exists.
    """
    if field in event:
        return True, event[field]
    if "." in field:
        cur: Any = event
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return False, None
        return True, cur
    return False, None


def _kind_for_item(modifiers: list[str]) -> str:
    """The comparison kind implied by an item's affix modifiers."""
    for mod in modifiers:
        if mod in _SUPPORTED_AFFIX_MODIFIERS:
            return _SUPPORTED_AFFIX_MODIFIERS[mod]
    return "plain"


# ---------------------------------------------------------------------------
# Condition-tree evaluation
# ---------------------------------------------------------------------------


def _eval_field_leaf(node: ConditionFieldEqualsValueExpression, event: dict[str, Any]) -> bool:
    present, event_value = _lookup_field(event, node.field)
    sigma_value = node.value
    if isinstance(sigma_value, SigmaNull):
        # `field: null` matches when the field is absent or explicitly null.
        return (not present) or event_value is None
    if not present:
        return False
    # The originating detection item may carry an affix / regex modifier; the
    # parsed leaf does not, so recover the kind from its source item.
    kind = "plain"
    source_item = getattr(node, "parent", None)
    if source_item is not None and hasattr(source_item, "modifiers"):
        kind = _kind_for_item([m.__name__ for m in source_item.modifiers])
    candidates = _event_values(event_value)
    return any(_match_scalar_value(c, sigma_value, kind) for c in candidates)


def _eval_keyword_leaf(node: ConditionValueExpression, event: dict[str, Any]) -> bool:
    """A bare keyword matches if it appears in *any* event value."""
    sigma_value = node.value
    for value in _flatten_all_values(event):
        if isinstance(sigma_value, SigmaString):
            if _match_string_value(value, sigma_value, "contains"):
                return True
        elif _match_scalar_value(value, sigma_value, "plain"):
            return True
    return False


def _flatten_all_values(obj: Any) -> list[Any]:
    """Every scalar value anywhere in the event (for keyword search)."""
    out: list[Any] = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_flatten_all_values(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_flatten_all_values(v))
    else:
        out.append(obj)
    return out


def _eval_node(node: Any, event: dict[str, Any]) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval_node(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval_node(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval_node(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _eval_field_leaf(node, event)
    if isinstance(node, ConditionValueExpression):
        return _eval_keyword_leaf(node, event)
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check(rule_yaml: str | None) -> bool | None:
    """Does ``rule_yaml`` parse + compile as a supported Sigma rule?

    ``None`` for NULL input. ``False`` for malformed YAML, a non-rule document,
    or a rule using unsupported modifiers/value types -- never raises.
    """
    if rule_yaml is None:
        return None
    try:
        compile_rule(rule_yaml)
        return True
    except SigmaWorkerError:
        return False
    except Exception:
        return False


def match(event_json: str | None, rule_yaml: str | None) -> bool | None:
    """Does the JSON event match the Sigma rule?

    ``None`` if either argument is NULL. Raises :class:`RuleParseError` /
    :class:`UnsupportedRuleError` for a bad rule (so the scalar surfaces a clear
    error); a malformed *event* JSON is treated as a non-match (``False``), since
    a single bad log row should never abort a column scan.
    """
    if event_json is None or rule_yaml is None:
        return None
    compiled = compile_rule(rule_yaml)  # may raise -> clear error to caller
    try:
        event = json.loads(event_json)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(event, dict):
        return False
    return _eval_node(compiled.condition, event)


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """Flat metadata view of a rule for ``sigma_rule_info``."""

    title: str | None
    id: str | None
    level: str | None
    status: str | None
    description: str | None
    product: str | None
    service: str | None
    tags: list[str]


def rule_info(rule_yaml: str | None) -> RuleInfo | None:
    """Parse a rule and return its metadata (``None`` for NULL input).

    Raises :class:`RuleParseError` for a rule that does not parse.
    """
    if rule_yaml is None:
        return None
    compiled = compile_rule(rule_yaml)
    rule = compiled.rule
    return RuleInfo(
        title=rule.title,
        id=str(rule.id) if rule.id is not None else None,
        level=rule.level.name.lower() if rule.level is not None else None,
        status=rule.status.name.lower() if rule.status is not None else None,
        description=rule.description,
        product=rule.logsource.product,
        service=rule.logsource.service,
        tags=[str(t) for t in rule.tags],
    )


def match_fields(rule_yaml: str | None) -> list[str] | None:
    """The sorted event field names a rule references (``None`` for NULL).

    Raises :class:`RuleParseError` for a rule that does not parse.
    """
    if rule_yaml is None:
        return None
    return list(compile_rule(rule_yaml).fields)
