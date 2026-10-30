# Synthetic callback fixture

This development fixture listens on `172.28.0.18:8080` inside the existing internal lab network. Enable its `callbacks` Compose profile explicitly. It has no published host port.

The `/bad/ssrf` and `/bad/xxe` routes recognize the existing reviewed callback marker requests. They can issue a single GET only to `http://172.28.0.17:8091/callback/<nonce>`. The fixed routes return the same response without contacting the collector. Inert negative requests also cause no callback. The XML fixture recognizes a narrow synthetic string pattern; it does not invoke an XML entity parser.

The application fixes the destination address and port, rejects other paths and URL components, ignores proxy environment settings, caps response reads, and does not follow redirects. The internal Docker network has no internet route. The collector restriction is application code, not a per-peer network firewall.

These fixtures exercise dispatch, receipt attribution and reporting. They are not independent vulnerability accuracy benchmarks, and the fixed case should remain inconclusive when absence of a callback cannot prove a pass.

For local configuration, the receiver origin is `http://172.28.0.17:8091`, and the target's callback peer is `172.28.0.18`. Scanner peers must be separately configured from the actual deployment, and must not overlap the target peer. Never use a guessed shared NAT address as target attribution.
