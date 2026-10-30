# Workers

**Empty in M0.** No worker image exists, and none should be added until the milestone
that owns it — a Dockerfile here would imply a capability the build does not have.

Build Plan §5.4 specifies two worker images and the boundary between them and the
control plane:

| Image | Contents | Milestone |
|---|---|---|
| `kali-tool` | ZAP CLI, Nuclei, testssl.sh, curl, bash — pinned by digest | M1 (supervisor), M3 (tools) |
| `browser` | Playwright + Chromium | M3 |
| supervisor | Trusted process that owns run identity, process groups and evidence collection. Runs **outside** the untrusted workers. | M1 |

Non-negotiable properties, from Build Plan §5.4, to be asserted by containment tests
before any of this is enabled:

- Workers get **no** database credentials, control-plane access, Docker socket or host
  mounts — only a per-scan scratch directory.
- The strong boundary (a dedicated worker VM or an equivalently evaluated isolation
  boundary) must be established and tested **before** any generated Python/Bash is
  enabled in M4, including scripts that only process local artifacts. A private Docker
  network alone does not satisfy this gate.
- Generated code receives only its permitted per-run artifacts and output location —
  never host credentials, control-plane access or another scan's data.
- Local-analysis scripts have no target-network capability at all. Networked scripts
  require the separately approved lab/staging profile.
- If the isolation boundary is missing, script execution stays **disabled** and M4 stays
  incomplete. It is never approximated.

All target traffic goes through the policy broker via a mandatory forward proxy; workers
have no direct egress. See `deploy/docker-compose.dev.yml`, which deliberately contains
no worker services.
