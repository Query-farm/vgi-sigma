"""Regenerate authored event records without using real logs or credentials."""

from pathlib import Path
import json
import hashlib


def main() -> None:
    """Write deterministic JSONL data and its provenance hash."""
    root = Path(__file__).resolve().parent
    paired = '{"EventID":4625,"LogonType":3}'
    records = [
        ("matched-a", "windows", "security", paired),
        ("matched-b", "windows", "security", paired),
        ("wrong-source", "linux", "auth", paired),
        ("unknown-source", None, None, paired),
        ("missing-field", "windows", "security", '{"EventID":4625}'),
        ("null-field", "windows", "security", '{"EventID":4625,"LogonType":null}'),
        ("other-event", "windows", "security", '{"EventID":4624,"LogonType":3}'),
        ("other-logon", "windows", "security", '{"EventID":4625,"LogonType":2}'),
        ("empty-object", "windows", "security", "{}"),
        ("array", "windows", "security", "[]"),
        ("malformed", "windows", "security", "{not-json"),
        ("missing", "windows", "security", None),
    ]
    text = "".join(
        json.dumps(
            dict(event_id=i, source_product=p, source_service=s, event_json=e), sort_keys=True
        )
        + "\n"
        for i, p, s, e in records
    )
    (root / "events.jsonl").write_text(text)
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "note": "Twelve authored synthetic records; source labels are fixture annotations, not authenticated provenance. No real account or log data.",
                "sha256": {"events.jsonl": hashlib.sha256(text.encode()).hexdigest()},
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
