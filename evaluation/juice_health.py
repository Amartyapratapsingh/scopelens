"""Evaluator-only health assertion over synthetic public product search; no answer-key API."""

import hashlib
import json

import httpx


def main():
    observations = []
    with httpx.Client(base_url="http://172.28.0.20:3000", timeout=10) as client:
        for name, value in [
            ("baseline", "apple"),
            ("negative", "scopelens-no-such-product"),
            ("true", "apple%')) AND 17=17-- "),
            ("false", "apple%')) AND 17=18-- "),
        ]:
            response = client.get("/rest/products/search", params={"q": value})
            response.raise_for_status()
            rows = response.json()["data"]
            observations.append(
                {
                    "name": name,
                    "count": len(rows),
                    "sha256": hashlib.sha256(response.content).hexdigest(),
                }
            )
    byname = {o["name"]: o for o in observations}
    assert byname["baseline"]["count"] > 0
    assert byname["baseline"]["sha256"] == byname["true"]["sha256"]
    assert byname["negative"]["count"] == byname["false"]["count"] == 0
    print(
        json.dumps(
            {
                "healthy": True,
                "condition": "paired public-search boolean behavior",
                "observations": observations,
            }
        )
    )


if __name__ == "__main__":
    main()
