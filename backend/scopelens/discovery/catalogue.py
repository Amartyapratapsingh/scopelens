"""Bounded, network-free import of observed requests and supplied API descriptions."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from bs4 import BeautifulSoup

from scopelens.domain.assessment import (
    DiscoveryCatalogue,
    DiscoveryGap,
    EndpointInstance,
    InputLocation,
    RelatedOriginGrant,
    RequestTemplate,
    stable_id,
)
from scopelens.domain.collection import CollectedResponse
from scopelens.domain.surface import AttackSurfaceMap
from scopelens.security.redaction import redact_text

SECRET = re.compile(
    r"password|passwd|secret|token|api[-_]?key|authorization|cookie|csrf|session", re.I
)
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
JS_ROUTE = re.compile(
    r"(?:fetch\s*\(|axios\.(?:get|post|put|patch|delete)\s*\(|url\s*:)\s*(['\"])([^'\"\n]{1,2048})\1"
)


def canonical_origin(url: str) -> str:
    parts = urlsplit(url)
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
    ):
        raise ValueError("invalid HTTP origin")
    host = parts.hostname.lower()
    host = f"[{host}]" if ":" in host else host
    port = parts.port or (443 if parts.scheme == "https" else 80)
    suffix = "" if port == (443 if parts.scheme == "https" else 80) else f":{port}"
    return f"{parts.scheme}://{host}{suffix}"


def _input(location, name, value=None, *, pointer=None, occurrence=0, required=False):
    secret = bool(SECRET.search(name))
    if isinstance(value, (dict, list)):
        value = None
    if isinstance(value, str):
        value = value[:4096]
        if (
            redact_text(value) != value
            or value == "[redacted]"
            or value.startswith(("Bearer ", "eyJ"))
        ):
            secret = True
    typ = (
        "null"
        if value is None and location == "json" and not secret
        else "boolean"
        if isinstance(value, bool)
        else "number"
        if isinstance(value, (int, float))
        else "string"
    )
    return InputLocation(
        location=location,
        name=name[:256],
        pointer=pointer,
        occurrence=occurrence,
        baseline_value=None if secret else value,
        value_type=typ,
        secret_ref=f"refresh:{location}:{pointer or name}:{occurrence}" if secret else None,
        required=required,
        mutable=not secret,
    )


def _json_inputs(value: Any, pointer="", *, depth=0):
    if depth > 12:
        return
    if isinstance(value, dict):
        for key, child in list(value.items())[:128]:
            token = str(key).replace("~", "~0").replace("/", "~1")
            if SECRET.search(str(key)):
                yield _input("json", str(key), None, pointer=f"{pointer}/{token}").model_copy(
                    update={"secret_ref": f"refresh:json:{pointer}/{token}", "mutable": False}
                )
            else:
                yield from _json_inputs(child, f"{pointer}/{token}", depth=depth + 1)
    elif isinstance(value, list):
        for n, child in enumerate(value[:128]):
            yield from _json_inputs(child, f"{pointer}/{n}", depth=depth + 1)
    else:
        name = pointer.rsplit("/", 1)[-1] or "$"
        yield _input("json", name, value, pointer=pointer)


def _complete_json(value, depth=0):
    if depth > 12:
        return False
    if isinstance(value, str):
        return len(value) <= 4096
    if isinstance(value, dict):
        return len(value) <= 128 and all(_complete_json(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return len(value) <= 128 and all(_complete_json(v, depth + 1) for v in value)
    return True


def _json_structure(value, pointer="", depth=0):
    if depth > 12 or not isinstance(value, (dict, list)):
        return {}
    result = {pointer: "object" if isinstance(value, dict) else "array"}
    items = list(value.items())[:128] if isinstance(value, dict) else list(enumerate(value[:128]))
    for key, child in items:
        if isinstance(key, str) and SECRET.search(key):
            continue
        token = str(key).replace("~", "~0").replace("/", "~1")
        result.update(_json_structure(child, f"{pointer}/{token}", depth + 1))
    return result


def _pairs(location, pairs):
    counts = Counter()
    result = []
    for name, value in pairs:
        if not name:
            continue
        result.append(_input(location, str(name), value, occurrence=counts[name]))
        counts[name] += 1
    return result


class _Builder:
    def __init__(self, origin, grants, limit):
        self.origin = canonical_origin(origin)
        self.grants = {}
        for grant in grants:
            key = canonical_origin(grant.origin)
            if key in self.grants:
                raise ValueError("duplicate related-origin grant")
            self.grants[key] = grant.purpose
        self.limit = limit
        self.templates = {}
        self.instances = {}
        self.gaps = []

    def gap(self, source, reason):
        if len(self.gaps) < 1000:
            self.gaps.append(DiscoveryGap(source=source, reason=reason))

    def add(
        self,
        url,
        source,
        *,
        method="GET",
        role="anonymous",
        content_type=None,
        inputs=(),
        observed=False,
        status=None,
        route_template=None,
        json_structure=None,
        baseline_complete=True,
    ):
        try:
            url = urljoin(self.origin + "/", url)
            parts = urlsplit(url)
            origin = canonical_origin(url)
            if any(ord(c) < 32 for c in url) or "\\" in url:
                raise ValueError("ambiguous URL")
        except (ValueError, TypeError):
            self.gap(source, "invalid_request_url")
            return
        method = str(method).upper()
        if method not in METHODS:
            self.gap(source, "unsupported_method")
            return
        all_inputs = tuple(
            sorted(
                [
                    *_pairs(
                        "query", parse_qsl(parts.query, keep_blank_values=True, max_num_fields=512)
                    ),
                    *inputs,
                ],
                key=lambda i: (i.location, i.pointer or i.name, i.occurrence),
            )
        )
        # Query parameters already supplied as OpenAPI definitions are merged with actual values.
        merged = {}
        for item in all_inputs:
            prior = merged.get(item.key)
            merged[item.key] = prior if prior and prior.baseline_value is not None else item
        all_inputs = tuple(merged.values())
        ctype = content_type.split(";", 1)[0].strip().lower() if content_type else None
        path = parts.path or "/"
        identity = [
            origin,
            route_template or path,
            method,
            role,
            ctype,
            [(i.key, i.value_type) for i in all_inputs],
            json_structure or {},
        ]
        ident = stable_id(identity)
        if ident not in self.templates and len(self.templates) >= self.limit:
            self.gap(source, "catalogue_limit")
            return
        authority = "primary" if origin == self.origin else self.grants.get(origin, "unapproved")
        template = RequestTemplate(
            id=ident,
            origin=origin,
            path=path,
            route_template=route_template or path,
            method=method,
            role_id=role,
            content_type=ctype,
            inputs=all_inputs,
            json_structure=json_structure or {},
            baseline_complete=baseline_complete,
            baseline_observed=observed,
            provenance=(source,),
            authority=authority,
        )
        previous = self.templates.get(ident)
        if previous:
            template = (previous if previous.baseline_observed else template).model_copy(
                update={
                    "baseline_observed": observed or previous.baseline_observed,
                    "provenance": tuple(sorted(set((*previous.provenance, source)))),
                }
            )
        self.templates[ident] = template
        instance = EndpointInstance(
            template_id=ident,
            path=path,
            role_id=role,
            source=source,
            status=status,
            baseline_observed=observed,
        )
        if len(self.instances) < self.limit * 4:
            self.instances[stable_id(instance.model_dump())] = instance
        else:
            self.gap(source, "instance_limit")

    def request(self, raw, source, role):
        post = raw.get("postData") or {}
        ctype = raw.get("content_type") or post.get("mimeType")
        if not raw.get("url"):
            self.gap(source, "request_url_missing")
            return
        inputs = []
        structure = {}
        complete = True
        for header in raw.get("headers", []):
            if isinstance(header, dict) and SECRET.search(str(header.get("name", ""))):
                inputs.append(_input("header", header["name"], header.get("value")))
        for cookie in raw.get("cookies", []):
            if isinstance(cookie, dict) and cookie.get("name"):
                inputs.append(
                    _input("cookie", cookie["name"]).model_copy(
                        update={"secret_ref": f"refresh:cookie:{cookie['name']}", "mutable": False}
                    )
                )
        if "json" in (ctype or ""):
            try:
                payload = (
                    raw.get("json")
                    if "json" in raw
                    else json.loads(post.get("text", raw.get("post_data", "")))
                )
                inputs += list(_json_inputs(payload))
                structure = _json_structure(payload)
                complete = _complete_json(payload)
            except (ValueError, TypeError):
                self.gap(source, "json_body_unavailable")
                complete = False
        elif "application/x-www-form-urlencoded" in (ctype or ""):
            params = post.get("params")
            inputs += _pairs(
                "form",
                [(p["name"], p.get("value")) for p in params if p.get("name")]
                if isinstance(params, list)
                else parse_qsl(
                    post.get("text", raw.get("post_data", "")),
                    keep_blank_values=True,
                    max_num_fields=512,
                ),
            )
        elif post or raw.get("post_data"):
            self.gap(source, "unsupported_request_body")
            complete = False
        self.add(
            raw.get("url", ""),
            source,
            method=raw.get("method", "GET"),
            role=raw.get("role_id", role),
            content_type=ctype,
            inputs=inputs,
            observed=True,
            status=raw.get("status"),
            json_structure=structure,
            baseline_complete=complete,
        )


def _resolve(document, value):
    if isinstance(value, dict) and "$ref" in value:
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {}
        value = document
        for token in ref[2:].split("/"):
            value = (
                value.get(token.replace("~1", "/").replace("~0", "~"), {})
                if isinstance(value, dict)
                else {}
            )
    return value if isinstance(value, dict) else {}


def _schema_sample(document, schema, *, depth=0):
    schema = _resolve(document, schema)
    if depth > 10:
        return None
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    if schema.get("enum"):
        return schema["enum"][0]
    if schema.get("type") == "object" or "properties" in schema:
        return {
            k: _schema_sample(document, v, depth=depth + 1)
            for k, v in list(schema.get("properties", {}).items())[:128]
        }
    # A type alone does not provide a valid ordinary baseline.
    return None


def _openapi(builder, document, source, role):
    servers = document.get("servers") or [{"url": builder.origin}]
    server = servers[0].get("url", builder.origin)
    base = urljoin(builder.origin + "/", server).rstrip("/")
    if "{" in base:
        builder.gap(source, "unresolved_server_variable")
        return
    for path, raw_item in list(document.get("paths", {}).items())[:2000]:
        item = _resolve(document, raw_item)
        for method, operation in item.items():
            if method.upper() not in METHODS or not isinstance(operation, dict):
                continue
            inputs = []
            concrete = path
            params = [*item.get("parameters", []), *operation.get("parameters", [])]
            for raw_param in params:
                param = _resolve(document, raw_param)
                location, name = param.get("in"), param.get("name")
                if location not in {"query", "path", "header", "cookie"} or not name:
                    continue
                value = param.get("example", _schema_sample(document, param.get("schema", {})))
                inputs.append(_input(location, name, value, required=param.get("required", False)))
                if location == "path" and value is not None and not SECRET.search(name):
                    from urllib.parse import quote

                    concrete = concrete.replace("{" + name + "}", quote(str(value), safe=""))
            body = _resolve(document, operation.get("requestBody", {}))
            content = body.get("content") or {None: {}}
            for ctype, descriptor in content.items():
                extra = []
                sample = descriptor.get(
                    "example", _schema_sample(document, descriptor.get("schema", {}))
                )
                if ctype and "json" in ctype:
                    extra = list(_json_inputs(sample))
                elif ctype == "application/x-www-form-urlencoded" and isinstance(sample, dict):
                    extra = _pairs("form", sample.items())
                elif ctype:
                    builder.gap(source, "unsupported_openapi_body")
                builder.add(
                    base + concrete,
                    source,
                    method=method,
                    role=role,
                    content_type=ctype,
                    inputs=[*inputs, *extra],
                    route_template=urlsplit(base).path + path,
                    json_structure=_json_structure(sample) if ctype and "json" in ctype else {},
                )


def discover_catalogue(
    origin: str,
    *,
    surface: AttackSurfaceMap | None = None,
    responses: tuple[CollectedResponse, ...] = (),
    browser_requests: tuple[dict, ...] = (),
    openapi_documents: tuple[dict, ...] = (),
    har_documents: tuple[dict, ...] = (),
    grants: tuple[RelatedOriginGrant, ...] = (),
    role_id: str = "anonymous",
    max_templates: int = 4000,
) -> DiscoveryCatalogue:
    """Import captures; supplied descriptions and discovered hosts grant no permission.

    Browser request records use HAR request fields, plus optional role_id/content_type/json.
    Values carrying credential names become refresh references before reaching the catalogue.
    """
    if not 1 <= max_templates <= 10000:
        raise ValueError("max_templates must be between 1 and 10000")
    builder = _Builder(origin, grants, max_templates)
    if surface:
        for form in surface.forms:
            method = form.method.upper()
            builder.add(
                urljoin(builder.origin, form.action),
                "surface:form",
                method=method,
                role=role_id,
                content_type="application/x-www-form-urlencoded" if method != "GET" else None,
                inputs=[
                    _input(
                        "query" if method == "GET" else "form", i.name, None, required=i.required
                    )
                    for i in form.inputs
                ],
            )
        for ep in surface.endpoints:
            builder.add(
                ep.url,
                f"crawl:{ep.discovered_via}",
                method=ep.method,
                role=role_id,
                observed=True,
                status=ep.status,
            )
    for n, response in enumerate(responses):
        source = f"response:{n}"
        builder.add(response.url, source, role=role_id, observed=True, status=response.status)
        if response.truncated:
            builder.gap(source, "truncated_response_discovery")
        if response.is_html:
            soup = BeautifulSoup(response.body_excerpt, "html.parser")
            for link in soup.select("a[href]"):
                builder.add(
                    urljoin(response.url, link.get("href", "")), source + ":link", role=role_id
                )
            for form in soup.find_all("form"):
                pairs = []
                for field in form.select("input[name],textarea[name],select[name]"):
                    if field.has_attr("disabled") or field.get("type") in {
                        "submit",
                        "button",
                        "file",
                        "reset",
                    }:
                        continue
                    if field.get("type") in {"checkbox", "radio"} and not field.has_attr("checked"):
                        continue
                    value = field.get("value", field.text if field.name == "textarea" else "")
                    if field.name == "select":
                        selected = field.find("option", selected=True) or field.find("option")
                        value = selected.get("value", selected.text) if selected else ""
                    pairs.append((field["name"], value))
                method = form.get("method", "GET").upper()
                builder.add(
                    urljoin(response.url, form.get("action") or response.url),
                    source + ":form",
                    method=method,
                    role=role_id,
                    content_type="application/x-www-form-urlencoded" if method != "GET" else None,
                    inputs=_pairs("query" if method == "GET" else "form", pairs),
                )
        if response.is_javascript or response.is_html:
            for match in JS_ROUTE.finditer(response.body_excerpt[:1048576]):
                route = match.group(2)
                if "${" in route:
                    builder.gap(source, "dynamic_javascript_route")
                    continue
                # Only literal method metadata is recognized; JS is never evaluated.
                method_match = re.match(r"axios\.(get|post|put|patch|delete)", match.group(0))
                options = response.body_excerpt[match.end() : match.end() + 512]
                fetch_method = re.match(
                    r"\s*,\s*\{\s*method\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]",
                    options,
                    re.I,
                )
                method = (
                    method_match.group(1).upper()
                    if method_match
                    else fetch_method.group(1).upper()
                    if fetch_method
                    else "GET"
                )
                if method not in {"GET", "HEAD"}:
                    builder.gap(source, "javascript_body_requires_capture")
                builder.add(
                    urljoin(response.url, route),
                    source + ":javascript",
                    role=role_id,
                    method=method,
                    baseline_complete=method in {"GET", "HEAD"},
                )
        if response.content_type and "json" in response.content_type:
            try:
                doc = json.loads(response.body_excerpt)
                if isinstance(doc, dict) and "openapi" in doc:
                    _openapi(builder, doc, source + ":openapi", role_id)
            except ValueError:
                pass
    for n, raw in enumerate(browser_requests):
        builder.request(raw, f"browser:{n}", role_id)
    for n, document in enumerate(openapi_documents):
        _openapi(builder, document, f"openapi:{n}", role_id)
    for n, document in enumerate(har_documents):
        entries = document.get("log", {}).get("entries", [])
        for j, entry in enumerate(entries[:10000]):
            builder.request(entry.get("request", {}), f"har:{n}:{j}", role_id)
        if len(entries) > 10000:
            builder.gap(f"har:{n}", "har_entry_limit")
    return DiscoveryCatalogue(
        origin=builder.origin,
        templates=tuple(builder.templates[k] for k in sorted(builder.templates)),
        instances=tuple(builder.instances[k] for k in sorted(builder.instances)),
        gaps=tuple(builder.gaps),
    )


def changing_json_fields(samples: list[Any]) -> tuple[str, ...]:
    """Identify observed response noise; never delete these fields from proof artifacts."""
    if len(samples) < 2:
        return ()
    flattened = [{i.pointer: i.baseline_value for i in _json_inputs(sample)} for sample in samples]
    keys = set().union(*(set(item) for item in flattened))
    missing = object()
    return tuple(
        sorted(
            k
            for k in keys
            if any(row.get(k, missing) != flattened[0].get(k, missing) for row in flattened[1:])
        )
    )
