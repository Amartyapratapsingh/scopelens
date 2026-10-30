# Mandatory forward proxy (Build Plan §5.3).
#
# Its own image with its own dependency set, for a concrete measured reason: mitmproxy
# imports `passlib.apache` unconditionally, and passlib's bcrypt backend calls
# `bcrypt.hashpw` with a secret longer than 72 bytes, which bcrypt 5.x raises on rather
# than truncating. With bcrypt 5.x installed `mitmdump` does not start at all.
#
# The backend keeps bcrypt 5.0.0 for the operator credential. Downgrading it to satisfy
# an unrelated component's transitive dependency would weaken authentication to fix a
# packaging conflict. See docs/OPEN_QUESTIONS.md Q-9.
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

# bcrypt is pinned below 5 so passlib's version detection works. The remaining log noise
# (`module 'bcrypt' has no attribute '__about__'`) is a trapped, non-fatal warning from
# passlib's probe; the proxy forwards traffic and generates its CA regardless.
RUN pip install --no-cache-dir \
        mitmproxy==12.1.2 \
        bcrypt==4.3.0 \
    && python -c "import mitmproxy, bcrypt; print('proxy image deps ok')"

# The addon is mounted read-only at run time from backend/scopelens/broker/mitm_addon.py,
# so the image carries no copy that could drift from the repository.

# mitmproxy writes its CA here. Mounted as a volume so the same CA can be mounted into
# workers, which trust it explicitly rather than the system store.
ENV MITMPROXY_CONFDIR=/var/lib/mitmproxy
RUN mkdir -p /var/lib/mitmproxy && chmod 700 /var/lib/mitmproxy

EXPOSE 8080

# `--set confdir` keeps the generated CA in the mounted volume. `-q` suppresses the
# interactive console; this runs headless.
ENTRYPOINT ["mitmdump", "--set", "confdir=/var/lib/mitmproxy", \
            "--listen-host", "0.0.0.0", "--listen-port", "8080", "-q"]

# Frozen release deployment uses this copy; development may bind-mount the same path.
COPY backend/scopelens/broker/mitm_addon.py /addons/scope_enforcer.py
