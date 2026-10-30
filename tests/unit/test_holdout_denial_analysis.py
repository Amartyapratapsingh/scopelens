"""Denial attribution must require the retained exact response body fingerprint."""

from evaluation.analyze_holdout_denials import DENIAL_HASH, attributed_responses


def responses(captures):
    return attributed_responses(
        {"captures": [{"ref": "accepted"}]},
        {"accepted": {"payload": {"captures": captures}}},
    )


def test_browser403_without_body_hash_is_unresolved():
    confirmed, unresolved = responses([{"status": 403, "name": "probe"}])
    assert not confirmed and len(unresolved) == 1


def test_exact_denial_hash_requires_error_status_and_accepted_reference():
    assert responses([{"status": 200, "body_hash": DENIAL_HASH}]) == ([], [])
    assert attributed_responses(
        {}, {"unaccepted": {"payload": {"captures": [{"status": 403, "body_hash": DENIAL_HASH}]}}}
    ) == ([], [])
    confirmed, unresolved = responses([{"status": 403, "body_hash": DENIAL_HASH}])
    assert len(confirmed) == 1 and not unresolved


def test_mixed403_origins_are_not_all_called_broker_denials():
    confirmed, unresolved = responses(
        [
            {"status": 403, "body_hash": DENIAL_HASH},
            {"status": 403, "body_hash": "another-body"},
        ]
    )
    assert len(confirmed) == len(unresolved) == 1
