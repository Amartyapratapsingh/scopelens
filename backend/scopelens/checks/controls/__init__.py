"""The implemented controls, bound to their registry ids.

This module is the join between the YAML registry (what a control *claims* — its proof rule,
fixtures, limits, review state) and the Python that evaluates it. The same id appears in both,
and a mismatch is caught two ways:

* the engine reports a registry entry with no implementation as an ``error`` outcome, so a
  planned control never silently disappears from the denominator
* a test asserts this mapping and the registry agree in both directions

Every control below follows the stance its registry entry declares (Spec §10.5). The stances
matter: an OBSERVE control may confirm a directly visible configuration, while a FLAG control
may only ever produce a candidate. A FLAG control that returned a confirmation would be
claiming a proof it is not permitted to obtain.
"""

from __future__ import annotations

from scopelens.checks.active import CONTROLS as ACTIVE_CONTROLS
from scopelens.checks.controls import api, browser, components, cookies, exposure, transport
from scopelens.checks.engine import Control

CONTROLS: tuple[Control, ...] = (
    # C01 Transport and encryption
    Control(
        check_id="SL-C01-TLS-01",
        evaluate=transport.evaluate_tls_certificate,
    ),
    Control(
        check_id="SL-C01-REDIR-01",
        evaluate=transport.evaluate_http_redirect,
    ),
    Control(
        check_id="SL-C01-HSTS-01",
        evaluate=transport.evaluate_hsts,
    ),
    Control(
        check_id="SL-C01-MIXED-01",
        evaluate=transport.evaluate_mixed_content,
    ),
    # C02 Server and session-cookie configuration
    Control(
        check_id="SL-C02-COOKIE-01",
        evaluate=cookies.evaluate_cookie_flags,
    ),
    Control(
        check_id="SL-C02-COOKIE-02",
        evaluate=cookies.evaluate_cookie_scope,
    ),
    # C04 Browser and cross-origin security
    Control(
        check_id="SL-C04-CSP-01",
        evaluate=browser.evaluate_csp,
    ),
    Control(
        check_id="SL-C04-FRAME-01",
        evaluate=browser.evaluate_frame_protection,
    ),
    Control(
        check_id="SL-C04-XCTO-01",
        evaluate=browser.evaluate_xcto,
    ),
    Control(
        check_id="SL-C04-REFERRER-01",
        evaluate=browser.evaluate_referrer_policy,
    ),
    # C05 Data exposure and privacy
    Control(
        check_id="SL-C05-ERRORS-01",
        evaluate=exposure.evaluate_verbose_errors,
    ),
    Control(
        check_id="SL-C05-LISTING-01",
        evaluate=exposure.evaluate_directory_listing,
    ),
    Control(
        check_id="SL-C05-FILES-01",
        evaluate=exposure.evaluate_exposed_files,
    ),
    Control(
        check_id="SL-C05-SECRETS-01",
        evaluate=exposure.evaluate_client_secrets,
    ),
    # C06 Components and dependency exposure
    Control(
        check_id="SL-C06-COMPONENT-01",
        evaluate=components.evaluate_component_versions,
    ),
    # C07 API exposure and integration controls
    Control(
        check_id="SL-C07-METHODS-01",
        evaluate=api.evaluate_method_exposure,
    ),
    Control(
        check_id="SL-C07-INVENTORY-01",
        evaluate=api.evaluate_api_inventory,
    ),
)


def controls_by_id() -> dict[str, Control]:
    return {control.check_id: control for control in CONTROLS}


CONTROLS += ACTIVE_CONTROLS
