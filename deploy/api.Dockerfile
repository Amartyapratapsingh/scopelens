# Development image for the API. Not a production image: it mounts source read-only
# and runs uvicorn without a process manager. The hardened deployment image is M5 work.
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

WORKDIR /app

# uv supplies a reproducible, lockfile-driven install.
COPY --from=ghcr.io/astral-sh/uv:0.12.11@sha256:79c6f4776b851471cc73b7d21d0cc834bb94383c292e83640d27eff512864df7 /uv /uvx /usr/local/bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock README.md alembic.ini ./

# Install exactly the locked set; fail the build rather than silently resolving.
RUN uv sync --frozen --no-install-project

COPY backend ./backend

RUN uv sync --frozen

ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8000

# Frozen runtime configuration; release deployment does not mount source.
COPY checks_registry /app/checks_registry
COPY skills /app/skills
COPY deploy /app/deploy
