# Isolated tool worker (Build Plan §5.4).
#
# This is the M1 *boundary*, not the M1 toolset. It carries curl and the pinned Python
# package so the read-only HTTP check can run; the Kali base and the ZAP / Nuclei /
# testssl.sh payload arrive in M3, when the adapters that use them are built. See
# docs/OPEN_QUESTIONS.md Q-11 — naming this image `kali-tool` today would advertise tools
# it does not contain.
#
# This container is treated as UNTRUSTED. Everything that makes it safe is applied from
# outside by the supervisor (network, capabilities, limits, read-only root); nothing in
# this image is trusted to enforce its own isolation.
#
# It receives no database credentials, no Redis URL, no Docker socket and no control-plane
# network membership. The only way it can reach a target is through the forward proxy.
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.12.11@sha256:79c6f4776b851471cc73b7d21d0cc834bb94383c292e83640d27eff512864df7 /uv /uvx /usr/local/bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project

COPY backend ./backend
RUN uv sync --frozen

# curl is installed so reviewed tooling has an HTTP client that honours *_PROXY without
# any application code. `ca-certificates` is present but the proxy CA is injected at run
# time via REQUESTS_CA_BUNDLE, so only the proxy's identity is trusted, not next to it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1

# Unprivileged. The root filesystem is read-only when the supervisor starts it; /tmp is a
# per-run tmpfs, which is the worker's only writable scratch.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin worker
USER 10001:10001

WORKDIR /tmp
