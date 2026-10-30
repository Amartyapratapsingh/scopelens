# Dedicated scanner workers

The final local deployment runs reviewed crawler/tool and Chromium containers in
`scopelens-workers`, a dedicated Lima VM. PostgreSQL, Redis, API, policy, model gateway,
evidence storage and the trusted supervisor remain outside that VM. Generated Python/Bash
continues to use its separate `scopelens-sandbox` VM.

The VM has no shared host folders, forwarded SSH agent or host Docker socket. The supervisor
uses a separate Docker daemon over mutual TLS. Only its client certificate directory is
mounted into the supervisor; those credentials are never passed to a scan worker.

## Start and operate

Prerequisites: Apple Silicon, Lima, Docker Desktop, an initialized `.env`, running labs,
and built/frozen ScopeLens images. This adds a 4 CPU / 4 GiB / 32 GiB VM.

```sh
make worker-vm-up
make freeze-release
make worker-vm-provision
make run-worker-vm
```

`run-worker-vm` first runs real boundary probes. A failure prevents that command from
activating the deployment. It then applies `docker-compose.worker-vm.yml` after the frozen
release configuration. Use this command for the qualified deployment; `make run` and
`make run-release` retain the earlier Docker Desktop development topology.

After rebuilding worker images, freeze and provision them again before starting scans.
Provisioning imports only the frozen image IDs and reports the deployed set. Do not provision
or restart the VM during an active scan. Stop only this VM with `limactl stop scopelens-workers`
after scans have finished. Other projects' Docker containers are unaffected.

Certificates live in git-ignored `runs/worker-vm`; client private keys are mode 0600.
Server/client certificates expire after 30 days. For renewal, finish scans, stop this
supervisor, move the existing certificate files into a protected backup directory, then
run provisioning to issue a fresh pair and restart with `make run-worker-vm`. Never copy the
private keys into documentation, images, reports or source control. A certificate error must
be fixed by renewal, not by disabling verification.

## Traffic boundary

Workers use an internal bridge with the `proxy` alias pointing at a fixed TCP relay. That
relay can connect only to `192.168.5.2:8098`, the host's enforcing ScopeLens proxy. It cannot
choose another upstream. Scope, DNS pinning, method/path, leases, revocation and request
budgets remain enforced by the existing broker on every request.

The VM firewall allows worker-to-relay TCP 8080 and relay-to-host TCP 8098. It denies
cross-worker connections, direct internet, metadata and host/control access. Bridge filtering
is explicitly enabled: the live listening-canary test reproduced peer access without it.
IPv6 forwarding from the worker bridge is denied. VM-originated outbound traffic is restricted
to the proxy, established replies, loopback and DHCP renewal. Network package installation is
only done during initial provisioning, before that restriction.

Only authenticated Docker control is forwarded to host loopback port 23976. All other
automatic TCP/UDP forwarding is disabled. The Lima management SSH connection remains local.
Firewall rules are installed by a systemd service after Docker and restored on boot.

### ARM browser compatibility

Provisioning applies `arm64.nosme` to this dedicated VM and reboots it before qualification.
The pinned Chromium renderer reproducibly crashed with SIGILL on staging when this Apple
guest advertised SME without SVE. Disassembly at the fault showed `cntd`, an SVE instruction.
With SME advertising disabled, the same worker captured page states and completed. The
qualification script requires this setting for the current pinned ARM deployment. Chromium
sandboxing, seccomp, BTI and pointer authentication remain enabled. Re-evaluate this workaround
when qualifying a new browser/kernel; it is not a recommendation for unrelated machines.
Logs: `runs/vm-browser-before-sme.stderr`, `runs/vm-browser-sme-fixed.log`.
The setting is documented in the [Linux kernel parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html).

The trusted supervisor still has administrative access to the **worker VM's** Docker daemon.
The trusted broker/TLS lane remain part of the control plane. This is a dedicated worker
boundary, not a claim that every trusted service is unprivileged or that a VM prevents every
possible escape.

## Measured qualification

`make verify-worker-vm` checks that the Docker daemon differs from the control daemon,
the VM has no host mounts, unauthenticated Docker access fails, direct destinations fail,
the proxy responds, a listening peer and its temporary file are inaccessible, and an actual
worker stops within 30 seconds. It writes `runs/worker-vm/boundary.json`.

Full API → crawler → tools → browser → proof → HTML/JSON runs are recorded separately under
`runs/worker-vm/paired-labs`. A boundary probe alone is not the end-to-end release gate.

References: [Docker mutual TLS](https://docs.docker.com/engine/security/protect-access/),
[Lima port forwarding](https://lima-vm.io/docs/config/port/).
