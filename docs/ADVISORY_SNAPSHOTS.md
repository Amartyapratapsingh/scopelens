# Component advisory snapshots

M2 accepts an operator-selected offline snapshot in OSV format. It never chooses a feed from target content or authenticates with discovered credentials.

Set `SCOPELENS_ADVISORY_BUNDLE_FILE` to a JSON file readable by the supervisor. In the supplied Compose deployment, put it under `checks_registry/advisories/` and use its container path, for example `/app/checks_registry/advisories/reviewed.json`. Restart the supervisor after changing environment configuration. Leave the variable unset when no corpus has been reviewed; C06 then reports unassessed and can withhold the overall score.

The wrapper requires:

```json
{
  "version": "reviewed-2026-09-25",
  "source": "operator-recorded upstream source and retrieval date",
  "packages": {"component fingerprint name": "ecosystem:package-name"},
  "records": []
}
```

Use real records obtained from the declared source. An empty example is not a vulnerability database. Every record needs `id`, `modified`, and an `affected` array using the [OSV schema](https://ossf.github.io/osv-schema/). Package mappings are explicit and case-normalized to the fingerprint name. The loader rejects malformed wrappers and snapshots over 10 MiB.

Supported matching: exact `affected.versions`, and stable numeric three-part versions in `SEMVER` ranges with `introduced`, `fixed`, `last_affected`, and `limit`. Other version schemes remain unassessed. Withdrawn records are ignored. Matching versions produce Potential candidates, never a confirmed CVE from a banner. Missing version or package mapping is a coverage gap. Results apply only to the snapshot's declared corpus, not every published advisory.

Each scan freezes the source, version, records and SHA-256 before execution. Later file edits do not change that scan's assessment. The snapshot is linked from its evidence manifest. The tests in `tests/unit/test_m2_advisories.py` use clearly synthetic identifiers for affected/fixed pairs; they do not claim those identifiers are real advisories.

The reviewed shipped corpus now contains 18 package identities and 651 records. Both
profile copies are hash-pinned as described in `COMPONENT_ADVISORIES.md`. Stable numeric
three-part `ECOSYSTEM` ranges are also supported for PyPI and Maven only, using numeric
release ordering and the same event bounds. Qualifiers, epochs, distro versions, GIT
ranges, missing mappings and other ecosystem schemes remain unassessed. An empty package
query is retained in the retrieval receipt but does not establish complete component
coverage. Server banner identity and vendor backports still require corroboration.
