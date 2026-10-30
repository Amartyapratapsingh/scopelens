"""Bounded, offline import boundary. Raw documents and sample values are discarded."""

import hashlib
import json
import re
from uuid import UUID

from pydantic import Field

from scopelens.discovery.catalogue import canonical_origin, discover_catalogue
from scopelens.domain.assessment import DiscoveryCatalogue, DiscoveryGap, Record

MAX_IMPORT_BYTES = 1_048_576
MAX_DEPTH = 24
MAX_NODES = 30_000


class ImportEnvelope(Record):
    scope_version_id: UUID
    kind: str = Field(pattern=r"^(openapi|har)$")
    role_id: str = Field(default="anonymous", pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    document: dict


def _bounded(value):
    stack, count = [(value, 0)], 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise ValueError("import structure exceeds limits")
        if isinstance(node, dict):
            if len(node) > 2000:
                raise ValueError("import object exceeds limits")
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            if len(node) > 2000:
                raise ValueError("import list exceeds limits")
            stack.extend((v, depth + 1) for v in node)
        elif isinstance(node, str) and len(node) > 65536:
            raise ValueError("import value exceeds limits")


def decode_envelope(raw: bytes) -> ImportEnvelope:
    """Caller exposes only a generic error; never JSON/Pydantic exception input."""
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("import exceeds byte limit")
    value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    _bounded(value)
    return ImportEnvelope.model_validate(value)


def _bounded_references(document):
    """Bound expanded local refs too: a tiny recursive schema can expand exponentially."""
    stack, count = [(document, (), 0)], 0
    while stack:
        value, ancestors, depth = stack.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("reference expansion exceeds limits")
        if isinstance(value, dict):
            ref = value.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/"):
                if ref in ancestors:
                    raise ValueError("recursive imported schema is unsupported")
                resolved = document
                for token in ref[2:].split("/"):
                    resolved = (
                        resolved.get(token.replace("~1", "/").replace("~0", "~"), {})
                        if isinstance(resolved, dict)
                        else {}
                    )
                stack.append((resolved, (*ancestors, ref), depth + 1))
            else:
                stack.extend((v, ancestors, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, ancestors, depth + 1) for v in value)


def catalogue_digest(catalogue):
    return hashlib.sha256(
        json.dumps(
            catalogue.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def normalize_import(envelope: ImportEnvelope, origin: str):
    from scopelens.domain.expansion import CatalogueImport

    document = envelope.document
    _bounded(document)
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_IMPORT_BYTES:
        raise ValueError("import exceeds byte limit")
    source_hash = hashlib.sha256(encoded).hexdigest()
    if envelope.kind == "openapi" and (
        not str(document.get("openapi", "")).startswith("3.")
        or not isinstance(document.get("paths"), dict)
    ):
        raise ValueError("OpenAPI 3 paths required")
    if envelope.kind == "openapi":
        _bounded_references(document)
    # HAR role labels are untrusted metadata. Each intake has one operator-selected role.
    if envelope.kind == "har":
        entries = document["log"]["entries"]
        if not isinstance(entries, list):
            raise ValueError("invalid HAR entries")
        document = {
            "log": {
                "entries": [
                    {"request": {**entry["request"], "role_id": envelope.role_id}}
                    for entry in entries
                ]
            }
        }
    kwargs = {"openapi_documents" if envelope.kind == "openapi" else "har_documents": [document]}
    discovered = discover_catalogue(origin, role_id=envelope.role_id, max_templates=500, **kwargs)
    templates = []
    for template in discovered.templates:
        # Paths and field names remain schema, never captured header/cookie/body values.
        # Drop credential-like opaque path segments instead of persisting them as inventory.
        if re.search(r"(?:Bearer\s|eyJ[A-Za-z0-9_-]{12,}|[A-Za-z0-9_-]{64,})", template.path):
            continue
        inputs = tuple(i.model_copy(update={"baseline_value": None}) for i in template.inputs)
        templates.append(
            template.model_copy(
                update={
                    "inputs": inputs,
                    "role_id": envelope.role_id,
                    "baseline_complete": False,
                    "baseline_observed": False,
                    "provenance": (f"import:{envelope.kind}:{source_hash}",),
                    "authority": "unapproved",
                    "path": template.route_template
                    if envelope.kind == "openapi"
                    else template.path,
                }
            )
        )
    # Parser diagnostics may include target-controlled strings. Return fixed descriptions.
    gaps = [DiscoveryGap(source=envelope.kind, reason="import_parser_gap") for _ in discovered.gaps]
    if re.search(rb'"\$ref"\s*:\s*"(?!#/)', encoded):
        gaps.append(DiscoveryGap(source=envelope.kind, reason="external_reference_not_loaded"))
    gaps.extend(
        DiscoveryGap(
            source=envelope.kind,
            reason="import_requires_reviewed_baseline_and_policy",
            template_id=t.id,
        )
        for t in templates
    )
    if len(templates) != len(discovered.templates):
        gaps.append(DiscoveryGap(source=envelope.kind, reason="credential_like_path_omitted"))
    catalogue = DiscoveryCatalogue(
        origin=canonical_origin(origin), templates=tuple(templates), gaps=tuple(gaps[:1000])
    )
    return CatalogueImport(
        scope_version_id=envelope.scope_version_id,
        kind=envelope.kind,
        role_id=envelope.role_id,
        source_sha256=source_hash,
        catalogue_sha256=catalogue_digest(catalogue),
        catalogue=catalogue,
    )
