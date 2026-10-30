"""Conservative path identity for admission, independently of query parameters."""

import posixpath
from urllib.parse import unquote


def canonical_path(target: str) -> str:
    path = target.split("?", 1)[0]
    for _ in range(4):
        decoded = unquote(path, errors="strict")
        if decoded == path:
            break
        path = decoded
    if (
        not path.startswith("/")
        or any(c in path for c in "%\\;?#")
        or any(ord(c) < 32 or ord(c) == 127 for c in path)
    ):
        raise ValueError("ambiguous or malformed request path")
    return "/" + posixpath.normpath(path).lstrip("/")


def path_interpretations(target: str) -> set[str]:
    """Check raw and decoded server interpretations before permitting a path."""
    variants = {canonical_path(target)}
    path = target.split("?", 1)[0]
    for _ in range(5):
        variants.add(path)
        variants.add("/" + posixpath.normpath(path).lstrip("/"))
        decoded = unquote(path, errors="strict")
        if decoded == path:
            break
        path = decoded
    return variants
