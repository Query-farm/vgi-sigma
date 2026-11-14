# Copyright 2026 Query Farm LLC - https://query.farm

"""Composed example queries: realistic SQL that combines several sigma objects.

Each example is defined exactly once here and referenced from the schema-level
``vgi.example_queries`` list (``worker.py``) *and* from the example list of the
object that drives the query (``scalars.py`` / ``tables.py`` / the
``supported_modifiers`` view), so the two copies can never drift apart.

Table functions here take only literal arguments (DuckDB rejects LATERAL
column parameters and subqueries for them), so a query that both introspects
and evaluates one rule passes the same rule literal to each function.
"""

from __future__ import annotations

# A three-rule library: two rules the engine evaluates and one that uses the
# unsupported ``cidr`` modifier, so ``sigma_check`` rejects it. Single-line YAML
# flow syntax keeps every rule inside a plain single-quoted SQL literal.
_RULE_LIBRARY_CTE = (
    "rules(rule_name, rule) AS (VALUES "
    "('encoded_powershell', '{title: Encoded PowerShell, level: high, "
    "logsource: {product: windows, category: process_creation}, "
    r"detection: {selection: {Image|endswith: \powershell.exe, CommandLine|contains: "
    '" -enc "}, condition: selection}}\'), '
    "('failed_network_logon', '{title: Failed Network Logon, level: medium, "
    "logsource: {product: windows, service: security}, "
    "detection: {selection: {EventID: 4625, LogonType: 3}, condition: selection}}'), "
    "('ssh_to_internal_net', '{title: SSH To Internal Network, level: low, "
    "logsource: {category: network_connection}, "
    "detection: {selection: {DestinationIp|cidr: 10.0.0.0/8, DestinationPort: 22}, condition: selection}}'))"
)

_FAILED_NETWORK_LOGON_RULE = (
    "'{title: Failed Network Logon, level: medium, tags: [attack.credential_access, attack.t1110], "
    "logsource: {product: windows, service: security}, "
    "detection: {selection: {EventID: 4625, LogonType: 3}, condition: selection}}'"
)

# --- sigma_check + sigma_match: run a rule library over a log ---------------
RULE_LIBRARY_HUNT_DESCRIPTION = (
    "Run a small rule library over an event log: keep only the rules sigma_check accepts "
    "(dropping the cidr rule the engine cannot evaluate), then join each event to every "
    "usable rule it matches (-> event 1 failed_network_logon, event 3 encoded_powershell)."
)
RULE_LIBRARY_HUNT_SQL = (
    "WITH " + _RULE_LIBRARY_CTE + ", "
    "logs(event_id, event) AS (VALUES "
    '(1, \'{"EventID": 4625, "LogonType": 3, "TargetUserName": "admin"}\'), '
    '(2, \'{"EventID": 4625, "LogonType": 2, "TargetUserName": "alice"}\'), '
    r"""(3, '{"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", """
    '"CommandLine": "powershell.exe -nop -enc SQBFAFgA"}\'), '
    r"""(4, '{"EventID": 1, "Image": "C:\\Windows\\explorer.exe", "CommandLine": "explorer.exe"}')), """
    "usable AS (SELECT rule_name, rule FROM rules WHERE sigma.main.sigma_check(rule)) "
    "SELECT l.event_id, u.rule_name FROM logs AS l "
    "JOIN usable AS u ON sigma.main.sigma_match(l.event, u.rule) "
    "ORDER BY l.event_id, u.rule_name"
)

# --- supported_modifiers + sigma_check: explain rejected rules -------------
UNSUPPORTED_MODIFIERS_DESCRIPTION = (
    "Explain why rules fail sigma_check: for each rejected rule in a library, list the field "
    "modifiers it uses that are absent from supported_modifiers (-> ssh_to_internal_net [cidr])."
)
UNSUPPORTED_MODIFIERS_SQL = (
    "WITH " + _RULE_LIBRARY_CTE + ", "
    "used AS (SELECT rule_name, unnest(regexp_extract_all(rule, '\\|(\\w+)', 1)) AS modifier "
    "FROM rules WHERE NOT sigma.main.sigma_check(rule)) "
    "SELECT rule_name, list(DISTINCT modifier ORDER BY modifier) AS unsupported_modifiers FROM used "
    "WHERE modifier NOT IN (SELECT modifier FROM sigma.main.supported_modifiers) "
    "GROUP BY rule_name ORDER BY rule_name"
)

# --- sigma_match_fields + sigma_match: no-match vs. blind spot -------------
MISSING_FIELDS_DESCRIPTION = (
    "Tell a real non-match from a blind spot: per host, did the event match the rule, and "
    "which fields the rule keys on are missing from it (-> dc01 matched with nothing missing; ws17 lacks LogonType; "
    "fw02 lacks both EventID and LogonType)."
)
MISSING_FIELDS_SQL = (
    "WITH logs(host, event) AS (VALUES "
    '(\'dc01\', \'{"EventID": 4625, "LogonType": 3, "TargetUserName": "admin"}\'), '
    '(\'ws17\', \'{"EventID": 4625, "TargetUserName": "bob"}\'), '
    '(\'fw02\', \'{"action": "deny", "dst_port": 3389}\')) '
    "SELECT l.host, sigma.main.sigma_match(l.event, " + _FAILED_NETWORK_LOGON_RULE + ") AS matched, "
    "coalesce(list(f.field ORDER BY f.field) FILTER (WHERE json_extract(l.event, '$.' || f.field) IS NULL), []) "
    "AS missing_fields "
    "FROM logs AS l CROSS JOIN sigma.main.sigma_match_fields(" + _FAILED_NETWORK_LOGON_RULE + ") AS f "
    "GROUP BY l.host, l.event ORDER BY l.host"
)

# --- sigma_rule_info + sigma_match: enrich alerts --------------------------
ALERT_ENRICHMENT_DESCRIPTION = (
    "Turn matches into alerts: label every event the rule matches with the rule's title, "
    "severity level and MITRE ATT&CK tags read from its header (-> events 1 and 3)."
)
ALERT_ENRICHMENT_SQL = (
    "WITH logs(event_id, event) AS (VALUES "
    '(1, \'{"EventID": 4625, "LogonType": 3, "TargetUserName": "admin"}\'), '
    '(2, \'{"EventID": 4624, "LogonType": 3, "TargetUserName": "admin"}\'), '
    '(3, \'{"EventID": 4625, "LogonType": 3, "TargetUserName": "svc_backup"}\')) '
    "SELECT l.event_id, i.title, i.level, i.tags FROM logs AS l "
    "CROSS JOIN sigma.main.sigma_rule_info(" + _FAILED_NETWORK_LOGON_RULE + ") AS i "
    "WHERE sigma.main.sigma_match(l.event, " + _FAILED_NETWORK_LOGON_RULE + ") "
    "ORDER BY l.event_id"
)

# All composed examples as {description, sql} entries, for the schema-level list.
COMPOSED_EXAMPLE_QUERIES: list[dict[str, str]] = [
    {"description": RULE_LIBRARY_HUNT_DESCRIPTION, "sql": RULE_LIBRARY_HUNT_SQL},
    {"description": ALERT_ENRICHMENT_DESCRIPTION, "sql": ALERT_ENRICHMENT_SQL},
    {"description": MISSING_FIELDS_DESCRIPTION, "sql": MISSING_FIELDS_SQL},
    {"description": UNSUPPORTED_MODIFIERS_DESCRIPTION, "sql": UNSUPPORTED_MODIFIERS_SQL},
]
