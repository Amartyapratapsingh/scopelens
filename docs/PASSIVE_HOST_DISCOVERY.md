# Passive host discovery

The coordinator collects CT names for the approved origin's registrable domain before
the baseline worker runs. Discovery uses fixed `crt.sh` and Cert Spotter endpoints,
then Google Public DNS over HTTPS for A/AAAA resolution. It never sends HTTP to a
discovered host. These provider requests do not consume the target request budget.
The result has no effect on destination admission, action grants, findings or scores.

The pinned Public Suffix List includes private suffixes, wildcard rules and exceptions.
It was obtained from `https://publicsuffix.org/list/public_suffix_list.dat`, version
`2026-10-07_07-28-19_UTC`, commit `3929462652695bad04f0a27afb600974014a3c8b`.
The file retains its Mozilla Public License notice. Unknown internal suffixes and IP
origins do not query public providers. Lab scans skip collection at the coordinator.

## Bounds and evidence

- CT response cap: 2 MiB decoded bytes, five-second request timeout per source.
- Retained names: 500, normalized through IDNA and restricted to the registrable domain.
- Resolution: at most 24 names, two queries per name, at most four DNS queries per second.
- DNS response cap: 64 KiB, two-second timeout per query.
- Source collection has a 25-second deadline. A blocking read can last up to its
  remaining request timeout; each chunk is also checked against the deadline.
- Process cache: at most 64 domains, one-hour successful/partial TTL, five-minute
  total-source-failure TTL. Cached observations retain their original timestamps.
- Each scan saves its immutable discovery snapshot in metadata and encrypted supervisor
  evidence. Repeated coordinator work reuses that snapshot. Dashboard reads do no I/O.

Cert Spotter [lists unexpired issuances in pages](https://sslmate.com/help/reference/ct_search_api_v1).
The bounded fallback retains only the first page, so success retains
`certificate_transparency_first_page_only` and any `crt_sh_source_unavailable` note.
Unavailable DNS and count/time caps remain explicit. `complete` means this bounded
collection finished; it never means all subdomains exist in the sources. Wildcards are
flagged and do not establish the existence of every covered name. A resolved address
does not prove ownership, a live web service or vulnerability.

## Dashboard and exports

`/hosts` and `/host-priorities` merge the saved snapshot with crawl/link inventory,
deduplicating hostnames and preserving primary-role evidence. CT/DNS names always start
with role `inventory_only`. Priority metadata does not schedule or authorize a scan.
Additive fields and coverage states are specified in `API_CONTRACT.md`.

Collection is enabled for production origins by default. Set
`SCOPELENS_PASSIVE_DISCOVERY_ENABLED=false` to disable it. Older scans have `not_run`
coverage. No migration or historical network backfill is performed.

Offline tests use injected HTTP transports. `tests/fixtures/passive/ct.json` is a
synthetic adversarial source fixture for duplicate, wildcard and suffix-lookalike names.
`certspotter-arkyon.json` records the public CT response fetched on 11 October 2026.
`dns-arkyon.json` replays normalized A/AAAA answers from that measured collection.

The owned `arkyon.dev` live check returned `arkyon.dev`, `games.arkyon.dev`,
`pointsolver.arkyon.dev`, and `www.arkyon.dev`; all four resolved. The saved receipt is
`runs/discovery-auth/passive-arkyon-live.json`. No HTTP was sent to these names. The
receipt remains partial because crt.sh was unavailable and the fallback queried only
the first page of unexpired issuances. The original receipt used the less precise
`certificate_transparency_recent_window` label, corrected in subsequent code and tests.
This is provider/inventory validation, not an assessment of those subdomains.
