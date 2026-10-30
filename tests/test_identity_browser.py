"""Real Chromium checks on synthetic loopback identities only."""

import pytest
from playwright.sync_api import sync_playwright
from pydantic import SecretStr
from tests.test_identity_expansion import capture, lab, matrix, profiles

from scopelens.domain.identity import IdentityProfile
from scopelens.identities.browser import BrowserIdentitySessions
from scopelens.identities.cors import check_credentialed_cors, origin
from scopelens.identities.sessions import SessionUnavailable


@pytest.mark.parametrize("vulnerable", [False, True])
@pytest.mark.parametrize("encoding", ["json", "form"])
def test_browser_roles_and_protected_cors(vulnerable, encoding):
    with lab(vulnerable=vulnerable) as base, lab() as foreign, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        identities = (
            *profiles(base),
            IdentityProfile(id="anonymous", role="anonymous", anonymous=True),
        )
        identities = tuple(
            p.model_copy(
                update={
                    "login": p.login.model_copy(
                        update={
                            "request": p.login.request.model_copy(
                                update={"body_encoding": encoding}
                            )
                        }
                    )
                }
            )
            if p.login
            else p
            for p in identities
        )
        sessions = BrowserIdentitySessions(
            identities,
            lambda _: SecretStr("synthetic-password"),
            lambda _: browser.new_context(service_workers="block"),
        )
        try:
            assert sessions.verify("a", action_owner="owner")
            assert sessions.verify("b", action_owner="owner")
            assert sessions.context("a", action_owner="owner") is not sessions.context(
                "b", action_owner="owner"
            )
            with pytest.raises(SessionUnavailable):
                sessions.context("a", action_owner="other-controller")
            result = check_credentialed_cors(
                matrix(base).objects[0],
                foreign + "/foreign",
                sessions,
                capture([]),
                allowed_foreign_origins=frozenset({origin(foreign)}),
                anonymous_id="anonymous",
                action_owner="owner",
            )
            assert result.state == ("confirmed" if vulnerable else "inconclusive")
            assert len(result.evidence_refs) == 3
            sessions.release("a", action_owner="owner")
            assert not sessions.context("a", action_owner="owner").cookies()
        finally:
            sessions.close()
            browser.close()
