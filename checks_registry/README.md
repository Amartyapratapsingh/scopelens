# Check registry

Build Plan §5.19. Every executable check is a registry entry. The schema lives in
`backend/scopelens/domain/registry.py`; entries are validated on load and the loader
**fails loudly** on an invalid entry rather than skipping it — a silently-skipped
control would look present while counting as unsupported.

```
controls/    one YAML file per canonical control
profiles/    assessment profile definitions (weights, eligibility, budgets)
```

## Review state

| State | Meaning |
|---|---|
| `experimental` | Schema and intent defined. Not supported. May run in a scan and may produce a candidate, but not a support claim. |
| `validated` | Has verified fixtures and a reviewed standards mapping. Still not a support claim. |
| `enabled` | **Only** state that counts as supported. |
| `retired` | Withdrawn. Kept for history; never runs. |

The loader enforces the promotion gate: a control cannot be moved to `validated` or
`enabled` unless `fixtures.verified: true`, `standards.mapping_review: reviewed` and
`last_reviewed` is set. That check exists so a control cannot be promoted by editing one
field.

**All three M0 controls are `experimental`.** The registry currently supports **zero**
controls, which is the honest state of a repository with no check code in it.

## Current entries

| ID | Category | Stance | Phase | Mandatory |
|---|---|---|---|---|
| `SL-C01-HSTS-01` | C01 Transport | OBSERVE | M2 | yes |
| `SL-C02-COOKIE-01` | C02 Server/session config | OBSERVE | M2 | yes |
| `SL-C04-XCTO-01` | C04 Browser/cross-origin | OBSERVE | M2 | yes |

All three are `max_requests: 0`: Project Specification §5.8 defines configuration
checks as pure functions over responses already collected during recon, so they add no
target traffic of their own.

## Standards mappings are deliberately incomplete

`standards.mapping_review` is `pending` on all three, and several identifier lists are
empty. An ASVS or OWASP-2025 identifier that has not been verified is left blank rather
than guessed — an invented identifier in a security control catalogue is a fabricated
claim, and a blank field is honest whereas a wrong one is not. A mapping review pass is
required before any control reaches `validated`. See `docs/OPEN_QUESTIONS.md` Q-4.

## Fixtures

Every entry names a vulnerable and a fixed counterpart. All three target the M0 lab
pair:

- `labs-bad` — `172.28.0.11`, deliberately misconfigured
- `labs-good` — `172.28.0.12`, the fixed counterpart

`fixtures.verified` is `false` on all three. `make labs-verify` demonstrates that the
fixture *pair* differs as designed, but that is not the same as the check having run
against them — and that check does not exist until M2.

## Validate

```bash
make check-registry
```
