# Plain-language findings

Updated 5 October 2026.

The frontend now uses a shared reviewed explanation catalogue covering all 46 shipped
control IDs. Each card shows the weakness, conditional impact, a practical fix, recorded
locations, and what the check did not demonstrate. Severity and confirmation state are
preserved. Informational severity is normalized for display and filtering.

The backend report writer uses the same catalogue for API responses and HTML/JSON
exports. Cached model prose cannot overwrite these descriptions. Raw redacted technical
observations and evidence remain available for review. Unknown controls retain their
existing description rather than receiving invented evidence or testing steps.

Verification:

- Frontend production build and typecheck pass.
- Plain-copy, capability/reach, and host-inventory unit tests: 36 passed.
- Plain-copy and dashboard/expanded-report regression tests: 26 passed.
- Built backend image imports the packaged catalogue: 46 controls.
- Regression tests confirm cached claims of login bypass or marks changes cannot replace
  the reviewed explanation, and severity/evidence references are unchanged.

Deployment:

- Frontend is live on port 5173.
- The backend image has been built as `scopelens-dev-supervisor` but has not been deployed.
- Scan `e69b4436-8221-4788-b286-2b9c754fdce3` was reporting during this update. Preserve it;
  deploy the report writer only after active scans finish, using the existing worker-VM
  deployment overlays. Do not interrupt the scan or restart all services for a prose update.
- The running backend's exported report still uses the previous text until that deployment.

These changes improve explanation; they do not add scanning coverage or establish any new
customer vulnerability. The saved portal assessment has four confirmed configuration
findings and one potential component candidate, with no confirmed high/critical finding.
