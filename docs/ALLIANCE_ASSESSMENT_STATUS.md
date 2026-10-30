# Alliance assessment status, 29 September 2026

The operator confirmed all college-owned `alliance.edu.in` subdomains are in scope.
Two newly registered public origins were assessed with GET/HEAD only, one request per
second, a 100-page ceiling, and a 30-minute scope wall-clock allowance. No credentials
were supplied or used. No other tenant sharing a server or IP was assessed.

## Latest completed runs

| Host | Scan ID | Pages captured | Duration | Observations | Reported coverage |
|---|---|---:|---:|---|---:|
| `portal.alliance.edu.in` | `f059781c-9921-42fc-a939-7b51a27f5732` | 31 | 160s | 5 configuration findings + 1 advisory candidate | 11.8% |
| `student.alliance.edu.in` | `824dbd61-28d2-40ff-b40e-08a682934589` | 35 | 173s | 5 configuration findings + 1 advisory candidate | 11.8% |

Both runs ended `completed_partial`. The crawler reported no time/page stop reason for
these runs. ZAP and Nuclei completed with no adapter errors. testssl remains partial;
conditional active checks were not enabled for these origins. Each run recorded 11
completed model calls across planning, verification, artifact analysis, and report prose.
An AI call completing is not proof of a vulnerability.

## What the observations mean

Each report contains the same six control families. Do not add them together as twelve
unique root causes without investigating whether the hosts share a deployment.

- Session-cookie configuration: the captured JSESSIONID cookie omits SameSite. This is
  a configuration observation, not a demonstrated CSRF attack or account compromise.
- Missing or ineffective CSP, HSTS, frame protection, and Referrer-Policy on captured
  responses. Per-location evidence remains in the reports; some locations are error pages.
- Component/version advisory matches remain potential. Exact build, vendor patches,
  vulnerable execution paths, and exploitability have not been confirmed.

No High/Critical vulnerability or access to student records was confirmed. No overall
numeric score is published because coverage requirements are not met.

## Product repairs verified

The scanner resource fix completed all 110 synthetic captures in 11 offline ZAP batches,
then passed the deployed lab scan and both public runs. See `SCANNER_RESOURCE_REPAIR.md`.
Seventy focused Python tests passed. The dashboard now lists discovered hosts with their
sources and assessed-versus-inventory status. It displays the crawl stop reason.

## Still incomplete

- The portal browser run could not capture its initial DOM after navigation. Stored HTTP
  responses contain a body element, so a frameset explanation is not supported. This
  requires a focused browser reproduction; raising all timeouts is not yet a proven fix.
- Authenticated student/staff access boundaries require dedicated test accounts and
  disposable records. None has been supplied. Public-page checks cannot substitute for them.
- Other college-owned discovered hosts have not been assessed in these two runs.
- Link discovery exists. Unlinked subdomain discovery through certificate-transparency
  sources is not implemented; the inventory must not claim to enumerate every subdomain.
- Long runs have coordinated time allowances, but durable crawl checkpoint/resume is not
  implemented. Increasing a runtime allowance is not equivalent to resumable execution.
- TLS tool support and unconfigured active checks remain visible coverage gaps.

## Saved reports

- Portal HTML: `runs/college-subdomains/portal.alliance.edu.in/export.html`
- Portal JSON: `runs/college-subdomains/portal.alliance.edu.in/export.json`
- Student HTML: `runs/college-subdomains/student.alliance.edu.in/export.html`
- Student JSON: `runs/college-subdomains/student.alliance.edu.in/export.json`

The earlier main-site report is preserved unchanged in `runs/fallback-validation/`.

## Host prioritization follow-up

The deployed dashboard now orders the observed hosts using forms, inputs, API signals,
coverage gaps, and advisory candidates. Ten of the 42 observed hosts match the confirmed
college domain. External dependencies remain inventory-only. Each owned host has
explicit next steps, and password-form workflows show that test identities are needed.
See `HOST_PRIORITIZATION.md` and the typed `/host-priorities` endpoint.

Public portal repeat `47177a9f-4493-40cd-a514-4aad69a4bf1f` preserved the same result:
31 HTTP pages, five confirmed configuration findings, one potential component candidate,
11.8% coverage, no High/Critical confirmation. The browser readiness repair passes its
isolated regression but did not resolve this site's zero-state capture. The report remains
partial. Saved artifacts: `runs/college-subdomains/portal-browser-recheck/`.
