# Component advisory assessment

The full backend deployment freezes an OSV snapshot into every scan's assessment plan.
The snapshot is packaged in the API/supervisor image at `checks_registry/advisories/osv.json`;
refreshing the file does not change an existing scan's evidence or score.

Current reviewed corpus, retrieved on 11 October 2026: 18 explicitly selected package
identities and 651 advisory records. The npm packages are jQuery, Bootstrap, Vue, Angular
core, React, Next, Nuxt, Express, AngularJS, lodash, axios and moment. Server mappings add
PyPI Django, Flask, Werkzeug and Gunicorn, plus Maven Tomcat Catalina and Jetty Server.
The legacy and expansion copies use SHA256
`c4a1a13a6a9bcda89880b90d0f1ca0311b13522e85222b5ec438f5be5053e20f`.
The coordinator rejects changed shipped bytes against this reviewed pin before freezing a
new plan. Custom operator-selected files retain the explicit snapshot hash in each scan.

This corpus does not identify operating-system packages, every web server or all
dependencies. nginx, Apache HTTP Server and PHP banners cannot establish a distribution,
OSV ecosystem or vendor build and remain unmapped rather than borrowing a distro advisory.

Refresh from the repository root:

```sh
uv run python scripts/fetch_advisories.py --output checks_registry/advisories/osv.json
```

The updater runs outside target workers and calls only the fixed OSV query endpoint. It
follows pagination, including empty pages with a continuation token. Loops, HTTP errors,
malformed records, excess pages, size limits and deadline failures prevent publication.
The previous snapshot stays intact. Successful updates retain package/page receipts, retrieval
time, response hashes and the original advisory revisions. Rebuild and freeze the deployment
to use an updated bundle. Review `PACKAGES` in the updater before extending the corpus.

The scanner extracts version candidates from named library banners and Angular's `ng-version`
attribute. A filename or incidental package mention does not establish a version. Exact version
and supported range matching produce **potential** findings, never confirmed CVEs: copied
banners, custom builds and vendor fixes still require corroboration. Unknown versions, missing
package mappings, unsupported version schemes and empty advisory corpora remain unassessed.
An unmatched component is not evidence that the whole application is free of vulnerable code.

Sources: [OSV query and pagination](https://google.github.io/osv.dev/post-v1-query/),
[OSV schema](https://ossf.github.io/osv-schema/).
