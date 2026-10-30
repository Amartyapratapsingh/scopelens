FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS python
FROM kalilinux/kali-rolling@sha256:30399bd65187e06525008dd13eecc2b3439d26a82b2c6b0ba32dee72bd843117
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless curl unzip ca-certificates openssl bash procps bsdextrautils xxd bind9-dnsutils libffi8 libsqlite3-0 libbz2-1.0 libreadline8 liblzma5 zlib1g && rm -rf /var/lib/apt/lists/*
COPY --from=python /usr/local /usr/local
COPY workers/vendor/gost-${TARGETARCH}.deb /tmp/gost.deb
COPY checks_registry/tooling/releases.json /tmp/tool-releases.json
COPY scripts/verify_tool_archive.py /tmp/verify_tool_archive.py
RUN python /tmp/verify_tool_archive.py /tmp/tool-releases.json gost-${TARGETARCH} /tmp/gost.deb && dpkg -i /tmp/gost.deb && openssl engine gost -t -c && rm /tmp/gost.deb /tmp/tool-releases.json /tmp/verify_tool_archive.py
COPY --from=ghcr.io/astral-sh/uv:0.12.11@sha256:79c6f4776b851471cc73b7d21d0cc834bb94383c292e83640d27eff512864df7 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY workers/vendor/zap.tar.gz /tmp/zap.tar.gz
COPY workers/vendor/testssl.tar.gz /tmp/testssl.tar.gz
COPY workers/vendor/nuclei-${TARGETARCH}.zip /tmp/nuclei.zip
RUN mkdir -p /opt/zap /opt/testssl && tar -xzf /tmp/zap.tar.gz -C /opt/zap --strip-components=1 && tar -xzf /tmp/testssl.tar.gz -C /opt/testssl --strip-components=1 && unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin && rm /tmp/*.gz /tmp/nuclei.zip
COPY checks_registry/tooling /app/tooling
COPY backend ./backend
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:/opt/zap:/opt/testssl:$PATH" HOME=/tmp/tool-home
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin worker
USER 10001:10001
WORKDIR /tmp

# Frozen runtime configuration; release deployment does not mount source.
COPY checks_registry /app/checks_registry
COPY skills /app/skills
COPY deploy /app/deploy
