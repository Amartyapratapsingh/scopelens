# Skills

**Empty in M0.** The loader is M4 work (Feature F-20); no skill pack is bundled here yet.

Build Plan §5.20 specifies reviewed Agent Skills-format knowledge packs, loaded by our
own loader, off by default:

| Pack | Use | Limit |
|---|---|---|
| Discovery interpretation | Runtime | Inventory → applicable checks; no automatic scope expansion |
| Browser exploration | Runtime | Allowed workflows, observation format, stopping rules |
| Evidence sufficiency | Runtime | Registered criteria, baseline controls, alternative explanations |
| False-positive challenge | Runtime | Counterevidence and uncertainty; cannot fabricate confirmation |
| Tool recovery | Runtime | Supported flags, version-specific errors, bounded retries |
| Remediation explanation | Runtime | Verified issue + technology context; no unsupported claims |

Rules to hold when this directory is populated:

- **Application policy controls permissions, regardless of a skill's declared tools.** A
  skill's `allowed-tools` metadata is not an authorization grant.
- **Never auto-load marketplace or target-supplied skills.** A scanned page cannot supply
  or influence a skill.
- Pin source revisions, review bundled scripts, and measure whether a pack actually
  improves outcomes before relying on it.
- Skill content is untrusted input for prompt-injection purposes: it cannot expand scope,
  change policy, install dependencies or alter a score.
- Check attribution and licence obligations before adapting third-party material.
