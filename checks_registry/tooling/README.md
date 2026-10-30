# M3 reviewed tool bundle

`releases.json` pins the official archives by SHA-256. `scripts/fetch_m3_tools.py` verifies them
before image build; no scan installs tools or downloads templates. Kali, Python and Playwright
base-image digests are in the Dockerfiles. Actual local image IDs and installed tool hashes are
recorded in `runtime.json` after verification.

- ZAP 2.17.0: bundled exim 0.16.0, reports 0.43.0, pscanrules 70. Imports local HAR without
  sending requests; only rules 10038, 10020, 10035 and 10021 run. Provider/egress credentials
  are removed from ZAP's environment. The HAR import in this pinned version predates the
  `sendRequests` option; adding that option creates a warning/nonzero exit. The option was
  introduced in [exim 0.22.0](https://www.zaproxy.org/docs/addons/exim/changelog/).
- Nuclei 3.11.1: only `nuclei-csp.yaml`, HTTP GET, no redirects, no OAST/headless/code/file
  templates, updates disabled. Proxy and header credentials are stripped by the broker.
- testssl.sh 3.2.4: only `--protocols`; `--proxy` points to a loopback-only admitted connection
  gate. `--ip proxy --nodns none` prevents its own target DNS resolution; the gate uses the
  broker's validated IP for every connection. No `--phone-out`, vulnerability family flags,
  arbitrary destinations or caller-supplied command fragments.
- Playwright 1.63.0 / Chromium 153.0.8010.12: fixed controller code, enabled Chromium sandbox.

`conditional-pack.json` records explicit per-service/per-origin configuration-probe approvals.
It grants no destination authority: profile, immutable scope and broker checks still apply.
The two synthetic-origin comparisons are observations, not credentialed CORS exposure proof.
The two redirect markers are inspected without following. No active injection control has been
promoted to supported in M3.
