"""Normalize browser request intentions before evidence leaves the reviewed worker."""

from scopelens.discovery import discover_catalogue

MAX_REQUEST_BYTES = 65_536


def request_templates(origin, *, url, method, headers, post_data=None):
    """No request is issued here. Secret values become refresh references in the parser."""
    if len(url.encode()) > 8192 or len((post_data or "").encode()) > MAX_REQUEST_BYTES:
        raise ValueError("browser request metadata exceeds capture limit")
    catalogue = discover_catalogue(
        origin,
        browser_requests=(
            {
                "url": url,
                "method": method,
                "headers": [{"name": key, "value": value} for key, value in headers.items()],
                "content_type": headers.get("content-type"),
                "post_data": post_data,
            },
        ),
        max_templates=1,
    )
    return tuple(
        template.model_copy(
            update={"baseline_observed": False, "provenance": ("browser:request_intent",)}
        )
        for template in catalogue.templates
    )
