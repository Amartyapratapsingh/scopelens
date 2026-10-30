"""Shared, evidence-bounded explanations for dashboard and exported reports."""

import json
from pathlib import Path

COPY: dict[str, dict[str, str]] = json.loads(
    Path(__file__).with_name("plain_language.json").read_text()
)


def explain(check_id: str, evidence_status: str, routes: list[str]) -> dict[str, str] | None:
    entry = COPY.get(check_id)
    if entry is None:
        return None
    confirmed = evidence_status == "confirmed"
    unique = list(dict.fromkeys(route for route in routes if route))
    where = (
        "Checked location: "
        + ", ".join(unique[:3])
        + (f" and {len(unique) - 3} more recorded locations." if len(unique) > 3 else ".")
        if unique
        else "The finding does not record a checked page or route."
    )
    observation = (
        entry["what"]
        if confirmed
        else (
            "This is a possible issue that still needs verification. "
            "The saved observation is a lead, not proof that someone can exploit the website."
        )
    )
    return {
        "title": entry["title"] if confirmed else "Possible issue: " + entry["title"],
        "what": where + " " + observation,
        "why": entry["why"] + " " + entry["limit"],
        "fix": entry["fix"],
    }
