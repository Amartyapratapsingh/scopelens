import pytest

from scopelens.checks.active import proof


def test_registry_covers_probe_requests_including_reconnected_https():
    from pathlib import Path

    import yaml

    from scopelens.checks.active import DEFINITIONS, HTTP_PROBE_LIMITS, sql_probes

    assert len(list(sql_probes({}))) == HTTP_PROBE_LIMITS["sql"]
    assert len(list(sql_probes({"sql_context": "like"}))) == HTTP_PROBE_LIMITS["sql"]
    for kind, limit in HTTP_PROBE_LIMITS.items():
        control = DEFINITIONS[kind][0]
        entry = yaml.safe_load(Path(f"checks_registry/controls/{control}.yaml").read_text())
        assert entry["allowed_action"]["max_requests"] >= 2 * limit


@pytest.mark.parametrize("kind", ["cors", "redirect"])
@pytest.mark.parametrize("status", [400, 404, 405, 410, 422])
def test_unavailable_route_does_not_establish_active_negative(kind, status):
    item = {"status": status, "origin_matches": False, "acac": False, "location_matches": False}
    assert proof(kind, [item, item]) is None


def test_duplicate_sql_measurement_is_not_repeatable_proof():
    samples = [
        {"name": name, "status": 200, "body_hash": value}
        for name, value in [
            ("baseline", "a"),
            ("negative", "b"),
            ("true1", "a"),
            ("false1", "b"),
            ("true2", "a"),
            ("false2", "b"),
        ]
    ]
    assert proof("sql", [*samples, samples[0]]) is None


@pytest.mark.parametrize("positive_group", ["single", "double", "numeric"])
def test_sql_contexts_require_a_complete_pair_and_do_not_mix_groups(positive_group):
    samples = []
    for group in ["single", "double", "numeric"]:
        for name in ["baseline", "negative", "true1", "false1", "true2", "false2"]:
            value = (
                "a"
                if name == "baseline" or (group == positive_group and name.startswith("true"))
                else "b"
            )
            samples.append({"name": name, "group": group, "status": 200, "body_hash": value})
    assert proof("sql", samples) is True
    assert proof("sql", samples[:-1]) is None
    assert proof("sql", [*samples, samples[0]]) is None


def test_policy_and_worker_browser_action_limits_match():
    from pathlib import Path

    import yaml

    services = yaml.safe_load(Path("deploy/docker-compose.m4.yml").read_text())["services"]
    assert (
        services["policy"]["environment"]["SCOPELENS_BROWSER_MAX_ACTIONS"]
        == services["supervisor"]["environment"]["SCOPELENS_BROWSER_MAX_ACTIONS"]
    )


def test_like_comparisons_distinguish_sql_evaluation_from_bound_search():
    import hashlib
    import sqlite3

    from scopelens.checks.active import sql_probes

    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE products(name TEXT)")
    db.executemany("INSERT INTO products VALUES (?)", [("apple",), ("orange",)])
    try:
        for vulnerable in [False, True]:
            captures = []
            for group, name, value in sql_probes({"sql_context": "like"}):
                try:
                    rows = (
                        db.execute(
                            f"SELECT name FROM products WHERE ((name LIKE '%{value}%'))"
                        ).fetchall()
                        if vulnerable
                        else db.execute(
                            "SELECT name FROM products WHERE name LIKE ?", ("%" + value + "%",)
                        ).fetchall()
                    )
                    status = 200
                except sqlite3.Error:
                    rows, status = [], 400
                captures.append(
                    {
                        "group": group,
                        "name": name,
                        "status": status,
                        "body_hash": hashlib.sha256(repr(rows).encode()).hexdigest(),
                    }
                )
            assert proof("sql", captures) is vulnerable
    finally:
        db.close()
