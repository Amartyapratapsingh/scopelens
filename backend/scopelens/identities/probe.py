"""Deterministic, bounded identity extraction shared by capture and verification."""

from __future__ import annotations

import hashlib
import json
import unicodedata

from bs4 import BeautifulSoup
from bs4.exceptions import ParserRejectedMarkup

from scopelens.domain.identity import SessionProbe

MAX_PROBE_BYTES = 1_048_576
MAX_IDENTITY_TEXT = 256
_UNSAFE = frozenset(
    {
        "script",
        "style",
        "template",
        "noscript",
        "input",
        "textarea",
        "select",
        "option",
        "button",
        "form",
        "head",
        "title",
        "meta",
        "link",
        "iframe",
        "object",
        "embed",
        "svg",
    }
)


class ParsedProbeDocument(dict):
    """Internal browser observation, never constructed from a target JSON document."""

    def __init__(self, identity: str, binding: str):
        super().__init__(identity=identity)
        self.probe_binding = binding


def html_content_type(value: str) -> bool:
    return value.split(";", 1)[0].strip().lower() in {"text/html", "application/xhtml+xml"}


def probe_binding(probe: SessionProbe) -> str:
    """Bind the entire declared request and extraction contract without retaining text."""
    encoded = json.dumps(
        probe.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def probe_binding_matches(probe: SessionProbe, binding: object) -> bool:
    # Legacy JSON proofs remain readable. HTML always requires its explicit contract.
    return (binding is None and probe.response_format == "json") or binding == probe_binding(probe)


def parse_probe_document(probe: SessionProbe, content: bytes) -> dict | list | None:
    """HTML returns only a digest at /identity. Invalid observations return no value.

    HTML uses strict UTF-8. Only leading/trailing whitespace is trimmed; internal
    whitespace, case and Unicode composition remain part of the exact identity.
    """
    if len(content) > MAX_PROBE_BYTES:
        return None
    if probe.response_format == "json":
        try:
            value = json.loads(content)
        except (ValueError, UnicodeError):
            return None
        return value if isinstance(value, (dict, list)) else None
    try:
        html = content.decode("utf-8", errors="strict")
    except UnicodeError:
        return None
    if "\x00" in html:
        return None
    try:
        soup = BeautifulSoup(html, "html.parser")
    except ParserRejectedMarkup:
        return None
    matches = soup.select(probe.html_selector, limit=2)
    if len(matches) != 1:
        return None
    node = matches[0]
    if (
        node.name in _UNSAFE
        or any(parent.name in _UNSAFE for parent in node.parents)
        or node.find(list(_UNSAFE)) is not None
        or soup.find(
            "input",
            attrs={"type": lambda value: isinstance(value, str) and value.lower() == "password"},
        )
        is not None
    ):
        return None
    raw_text = node.get_text(separator="", strip=False)
    if any(
        unicodedata.category(char).startswith("C") and char not in "\r\n\t" for char in raw_text
    ):
        return None
    text = raw_text.strip()
    if (
        not text
        or len(text) > MAX_IDENTITY_TEXT
        or len(text.encode("utf-8")) > 1024
        or "\ufffd" in text
        or any(unicodedata.category(char).startswith("C") for char in text)
        or any(str(field.get("value", "")).strip() == text for field in soup.find_all("input"))
        or any(field.get_text().strip() == text for field in soup.find_all("textarea"))
    ):
        return None
    return ParsedProbeDocument(
        "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(), probe_binding(probe)
    )


def response_probe_document(response, probe: SessionProbe):
    if probe.response_format == "html":
        if hasattr(response, "content"):
            if not html_content_type(response.headers.get("content-type", "")):
                return None
            return parse_probe_document(probe, response.content)
        # Browser collector adapters already received the parsed observation. Plain
        # target JSON cannot claim this in-process provenance marker.
        document = response.json()
        return (
            document
            if isinstance(document, ParsedProbeDocument)
            and document.probe_binding == probe_binding(probe)
            else None
        )
    try:
        return response.json()
    except ValueError:
        return None


def response_probe_value(response, probe: SessionProbe):
    from scopelens.identities.sessions import pointer

    return pointer(response_probe_document(response, probe), probe.identity_pointer)
