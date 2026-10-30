# Expansion deployment acceptance

Updated 11 October 2026. This ledger distinguishes historical owned-lab acceptance from
source/local tests. No experimental control is independently qualified or promoted here.
Historical artifacts remain in ignored `runs/`; their dates and limitations remain part
of the acceptance claim. A later source change requires another deployment gate.

## Control ledger

Every experimental entry in the current 46-control registry is listed below. A fixture
pair is source evidence. It does not confer deployed acceptance. The 17 enabled passive
configuration controls retain their earlier paired lab gate recorded in `BACKEND_STATUS.md`.

| Control | Fixture pair | Deployment acceptance | Evidence or missing gate |
|---|---|---|---|
| SL-C03-XSS-01 | labs-good/labs-bad active pair | Historical pair accepted, experimental | `runs/worker-vm/paired-labs`, 26 September; no independent qualification |
| SL-C03-HTML-01 | labs-good/labs-bad; authenticated browser pair | Historical pair accepted, experimental | `runs/authenticated-browser-reach-deployed`; unrelated crawl gaps retained |
| SL-C03-SQL-01 | labs-good/labs-bad; discovery pair | Historical pair accepted, experimental | `runs/discovery-deployed`; four discovered input locations |
| SL-C04-REDIRECT-01 | labs-good/labs-bad; authenticated HTTP pair | Historical pair accepted, experimental | `runs/authenticated-inputs-deployed` |
| SL-C04-CORS-01 | labs-good/labs-bad configuration pair | Historical pair accepted, experimental | Header/configuration proof only; does not establish credentialed protected-data exposure |
| SL-C03-DOMXSS-01 | `tests/browser/test_expanded_browser.py`; discovery pair | Historical discovery pair accepted, experimental | `runs/discovery-deployed`; DOM-only case |
| SL-C04-HDRINJECT-01 | `tests/unit/test_expanded_active.py` | Not accepted | Deployed vulnerable/fixed raw-header boundary and report gate absent |
| SL-C05-CONFIG-02 | `labs/expansion_tools/app.py` True/False | Not accepted | Local exposure/Nuclei pair exists; supervisor/broker report gate absent |
| SL-C05-DEBUG-02 | Same exposure pair | Not accepted | Deployed positive, fixed and look-alike report gate absent |
| SL-C05-MANAGEMENT-01 | Same exposure pair | Not accepted | Deployed unauthenticated synthetic management-data pair absent |
| SL-C05-PRIVATE-02 | Same exposure pair | Not accepted | Deployed private-material classification/redaction pair absent |
| SL-C05-SOURCEMAP-01 | Same exposure pair | Not accepted | Deployed private source-map versus public source-map pair absent |
| SL-C09-OBJECT-01 | `labs/expansion_identity/app.py` vulnerable/fixed; academic pair | Not accepted | Local independent identity/readback tests exist; deployed forbidden-object pair absent |
| SL-C09-FUNCTION-01 | Same identity pair | Not accepted | Deployed forbidden-function pair absent |
| SL-C09-TENANT-01 | Same identity pair | Not accepted | Deployed distinct-tenant pair absent |
| SL-C09-PROPERTY-01 | Same identity pair | Not accepted | Deployed forbidden-property/redacted-view pair absent |
| SL-C08-SESSION-01 | Same identity pair; lifecycle fixture tests | Not accepted | Readiness probes are not lifecycle proof; deployed rotation/logout/expiry pair absent |
| SL-C04-CORSDATA-01 | `tests/browser/test_credentialed_cors_runtime.py`, bad/fixed | Vulnerable confirmed; fixed inconclusive, experimental | `runs/backend-gaps-cors-c208c00/receipts.json`: vulnerable confirmed; fixed inconclusive (blocked read observed), with no fixed-control pass or completion credit. Cross-origin same-site ports only; no cross-site cookie-policy qualification |
| SL-C03-STOREDXSS-01 | `tests/browser/test_browser_workflows.py`, bad/fixed | Historical browser pair accepted, experimental | `runs/backend-browser-final-live.log`, `runs/authenticated-browser-deployed`; cleanup limitations remain recorded |
| SL-C04-CSRF-01 | Same browser workflow pair | Historical browser pair accepted, experimental | Same six-case browser gate; controlled benign action only |
| SL-C10-UPLOAD-01 | Same browser workflow pair | Historical browser pair accepted, experimental | Same six-case browser gate; benign file/declared serving policy only |
| SL-C07-SSRF-02 | `labs/expansion_callbacks/verify.py` and owned callback lab | Historical callback pair accepted, experimental | `runs/callbacks-deployed`; fixed absence remains inconclusive, signed target HTTP attribution required |
| SL-C03-XXE-02 | Same callback pair, actual SAX parser | Historical callback pair accepted, experimental | Same four-case callback gate; no local-file-read claim |
| SL-C09-MASS-01 | `labs/expansion_workflows/app.py` vulnerable/fixed | Not accepted | Deployed disposable-record mutation/readback/cleanup pair absent |
| SL-C09-GRAPHQL-01 | Same HTTP workflow pair | Not accepted | Deployed bounded forbidden-field query pair absent |
| SL-C05-CACHE-01 | Same HTTP workflow pair | Not accepted | Deployed separate-context private-marker cache pair absent |
| SL-C10-TRAVERSAL-01 | Same HTTP workflow pair | Not accepted | Deployed designated canary versus fixed pair absent |
| SL-C03-TEMPLATE-01 | Same HTTP workflow pair | Not accepted | Deployed benign-expression/literal-control pair absent |
| SL-C11-WORKFLOW-01 | Same HTTP workflow pair; academic mutation pair | Not accepted | Deployed invariant/readback/cleanup pair absent; local academic tests are development evidence |

## Tooling and investigation gates

- ZAP passive HAR analysis retains its existing gate. Native ZAP active source now
  includes a network-none launcher, trusted Docker file channel, signed private broker
  routes and proxy enforcement. Commit `2519598` passed 2,079 tests in its clean
  committed checkout. The shipped approval manifest remains empty and zero dispatch
  is tested. The proposed finite 40012 catalog is in `ZAP_ACTIVE_ALLOWLIST_PROPOSAL.md`.
  Deployed b0b123a native gate is **not accepted**: labs-bad scan
  `c04b29c0-103a-4f68-9e0a-150ee10eb408` returned a native launcher/channel error,
  zero admitted grant requests and no observations; fixed case was not run. Root cause
  is not established by the masked exception. Official image/env/mount/readiness and
  shipped-manifest restoration passed. Evidence:
  `runs/backend-gaps-native-lab-b0b123a-retry/receipts.json`. Operator-authorized future
  origin activation remains conditional on the successful pair and explicit go-ahead.
  Shipped approval list is empty; no external-dast origin is enabled.
- Supervisor capability measurement is **accepted for numeric inventory and export
  parity** on deployed b0b123a fresh lab scan
  `232c3ccd-3312-4e81-8cf7-35698de018a3`: strict source/image/snapshot replay measured
  five installed tools and twelve executable controls. The Chromium branded-banner fix
  is now deployed and remeasured; the earlier c208c00 gate failure remains historical.
  Evidence: `runs/backend-gaps-capability-b0b123a/receipts.json`. The scan is partial;
  this acceptance does not establish assessment completion or family qualification.
- Anonymous GET reflection dispatch, supplied-session read-only access investigations and
  read-only stored callback receipt verification are connected in source. Their local
  context/proof tests do not establish deployed adaptive acceptance or an equal-budget gain.
  Login-based access follow-ups and authenticated browser reflection follow-ups remain blocked.
  Supplied access follow-ups retain their own evidence and graph proof; they do not merge
  separate attempts into baseline access-control coverage.
- Resource-only origins remain an explicit assessment gap. A discovery record does not
  authorize requests or credential propagation. No resource-only deployment acceptance is
  added by this work.

## Failed deployment attempt and pending gates

The 11 October CORS attempt used scan `37e6601d-1366-4556-b612-68d0e33abb90`.
The browser lab fixture at `.16` was restored and became healthy. The supervisor could not
connect to `host.docker.internal:23976`; Lima reported no `scopelens-workers` instance in
this environment. No CORS proof/control outcome was captured. Cancellation returned 200.
`runs/backend-gaps-cors-live.log` records the failed verifier, and
`runs/backend-gaps-lab-recovery.log` records fixture startup and the edge-health limitation.
No deployed acceptance or clean fixed result is inferred from this attempt.
The integration lane subsequently restored the worker VM and activated its older
`8a982ed` frozen candidate. That recovery does not rerun this CORS gate or accept the
new capability/adaptive source. Those specific gates still need matching runtime evidence.
