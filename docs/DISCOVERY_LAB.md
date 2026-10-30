# Discovery development gate

This optional pair tests the deployed crawler, browser, request planner, reviewed HTTP and
browser collectors, evidence intake and report path. It is development evidence. It is not
an independent holdout and cannot promote a control to qualified.

With the backend already running on its dedicated worker VM:

```sh
make labs-up-discovery
make verify-discovery
```

The pair uses two exact operator lab bindings on the internal fixture network. No host port
is published. Each SQL request uses a fresh in-memory database with one synthetic product;
POST operations are read-only searches. No real records or credentials are involved.

The evaluator first starts `external-discovery-v2` with an empty assessment configuration.
The fixture exposes opaque routes through HTML links, a form, a native SPA request intention
and an OpenAPI schema. Static discovery cannot find the constructed JSON route. The browser
records its request shape while keeping its unreviewed POST blocked.

The evaluator reads the safe paginated template-review API for the exact persisted plan
revision. It checks scan/scope/catalogue binding and joins proof inputs by stable opaque IDs.
Public evidence exports intentionally redact fields that prevent reconstructing private request
templates. No export redaction is disabled. The second scan receives only policies for those
discovered template IDs. No endpoint template, input baseline or fixture answer is submitted
to the scanner.

The gate requires completed SQL proof for query, form, nested JSON and path inputs, and
browser proof for a DOM-only rendering case. Both variants expose identical routes and ordinary
content. The fixed counterpart must produce no confirmed DOM finding and passing SQL evidence
for all four input locations. Unrelated incomplete inputs remain in report coverage.

HTML/JSON reports and receipts are saved under `runs/discovery-deployed`. Failed assertions
leave existing scan results available for inspection. A gate timeout requests cancellation of
its own scan. This command accepts no external target URL.
