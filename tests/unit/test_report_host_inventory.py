from types import SimpleNamespace

from scopelens.writer.report import _host_inventory


def test_primary_inventory_uses_hostname_so_previous_assessments_can_match():
    surface = SimpleNamespace(
        origin="https://www.school.test:8443",
        payload={
            "hosts": [{"host": "portal.school.test", "role": "inventory_only", "evidence": "link"}]
        },
    )
    inventory = _host_inventory(surface)
    assert inventory[0]["host"] == "www.school.test"
    assert inventory[0]["role"] == "primary"
    assert inventory[1]["host"] == "portal.school.test"
