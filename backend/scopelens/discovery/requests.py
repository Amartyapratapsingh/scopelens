"""Render a frozen request for a broker-bound client. Never resolve secrets in a model."""

from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote, urlencode

from scopelens.domain.assessment import RequestTemplate


def _assign(root, pointer, value):
    tokens = (
        [t.replace("~1", "/").replace("~0", "~") for t in pointer.lstrip("/").split("/")]
        if pointer
        else []
    )
    if not tokens:
        return value
    if root is None:
        root = [] if tokens[0].isdigit() else {}
    cursor = root
    for n, token in enumerate(tokens):
        last = n == len(tokens) - 1
        default = None if last else [] if tokens[n + 1].isdigit() else {}
        if isinstance(cursor, list):
            if not token.isdecimal() or int(token) > 10000:
                raise ValueError("invalid JSON array index")
            index = int(token)
            while len(cursor) <= index:
                cursor.append(None)
            if last:
                cursor[index] = value
            else:
                if cursor[index] is None:
                    cursor[index] = default
                cursor = cursor[index]
        elif isinstance(cursor, dict):
            if last:
                cursor[token] = value
            else:
                cursor = cursor.setdefault(token, default)
        else:
            raise ValueError("inconsistent JSON structure")
    return root


def render_request(
    template: RequestTemplate,
    mutations: Mapping[str, Any] | None = None,
    secret_resolver: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """Return httpx-compatible method/url/headers/content or json arguments.

    Mutation keys are InputLocation.key. This does not send requests or authorize actions.
    Return values may contain freshly resolved credentials and must never be persisted or
    given to a model. Call only inside the trusted transport boundary, then discard.
    """
    mutations = mutations or {}
    locations = {i.key: i for i in template.inputs}
    if set(mutations) - set(locations):
        raise ValueError("unknown mutation location")
    query, form, cookies = [], [], []
    headers = {}
    path = template.path
    json_body = None
    has_json = bool(template.json_structure)
    for pointer, kind in sorted(
        template.json_structure.items(), key=lambda item: (item[0].count("/"), item[0])
    ):
        json_body = _assign(json_body, pointer, {} if kind == "object" else [])
    for item in template.inputs:
        if item.key in mutations and not item.mutable:
            raise ValueError("cannot mutate credential input")
        if item.secret_ref:
            if secret_resolver is None:
                raise ValueError("secret refresh required")
            value = secret_resolver(item.secret_ref)
            if not value or any(c in value for c in "\r\n"):
                raise ValueError("invalid refreshed secret")
        else:
            value = mutations.get(item.key, item.baseline_value)
        if value is None and item.required:
            raise ValueError("required baseline missing")
        if item.location == "query":
            query.append((item.name, "" if value is None else str(value)))
        elif item.location == "form":
            form.append((item.name, "" if value is None else str(value)))
        elif item.location == "path":
            if value is None:
                raise ValueError("path baseline missing")
            # Concrete values are replaced only when the supplied route template names
            # the segment. Never search-and-replace an arbitrary number in a URL.
            path = template.route_template
            for field in (i for i in template.inputs if i.location == "path"):
                selected = mutations.get(field.key, field.baseline_value)
                if field.secret_ref:
                    raise ValueError("secret path identifiers cannot be rendered")
                if selected is None:
                    raise ValueError("path baseline missing")
                path = path.replace("{" + field.name + "}", quote(str(selected), safe=""))
        elif item.location == "json":
            has_json = True
            json_body = _assign(json_body, item.pointer, value)
        elif item.location == "header":
            if item.name.lower() in {
                "host",
                "proxy-authorization",
                "x-scopelens-egress",
                "x-scopelens-reviewed-probe",
                "content-length",
                "transfer-encoding",
            }:
                raise ValueError("cannot supply transport authority header")
            if any(c in item.name + str(value) for c in "\r\n"):
                raise ValueError("invalid header")
            headers[item.name] = str(value)
        elif item.location == "cookie":
            if any(c in item.name + str(value) for c in "\r\n;"):
                raise ValueError("invalid cookie")
            cookies.append(f"{item.name}={value}")
    if "{" in path or "}" in path:
        raise ValueError("unresolved path")
    if cookies:
        headers["Cookie"] = "; ".join(cookies)
    if template.content_type:
        headers["Content-Type"] = template.content_type
    rendered = {
        "method": template.method,
        "url": template.origin + path + ("?" + urlencode(query) if query else ""),
        "headers": headers,
    }
    if has_json:
        rendered["json"] = json_body
    elif form:
        rendered["content"] = urlencode(form).encode()
    return rendered
