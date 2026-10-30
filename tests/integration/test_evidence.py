"""Trusted evidence intake (Build Plan §5.5; test suite §8 "Evidence").

The claim these tests protect is specific: a fabricated or unattributable artifact cannot
become evidence that a proof rule accepts. The suite checks the ordering the intake
guarantees (cap, redact, hash, store) and the provenance that makes an artifact
attributable at all.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.domain.evidence import EvidenceOrigin, RedactionState
from scopelens.evidence import intake
from scopelens.evidence.store import EvidenceStoreError, LocalDiskEvidenceStore, content_ref
from scopelens.security.redaction import REDACTED

pytestmark = pytest.mark.db


class TestProvenance:
    def test_evidence_records_who_captured_it(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, task = queued_scan
        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.BROKER,
            producer="policy_broker",
            content=b"observed response",
            task_id=task.id,
            run_id="run-1",
        )

        assert record.scan_id == str(scan.id)
        assert record.task_id == str(task.id)
        assert record.run_id == "run-1"
        assert record.origin is EvidenceOrigin.BROKER
        assert record.scope_version_id == str(scan.scope_version_id)
        assert record.scope_content_hash
        assert record.content_hash
        assert record.captured_at is not None

    def test_a_scope_is_required_for_attribution(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        """Evidence that cannot be tied to an authorization is not evidence."""
        scan, _task = queued_scan
        scan.scope_version_id = None  # type: ignore[assignment]
        with pytest.raises(intake.EvidenceIntakeError):
            intake.record_evidence(
                db_session,
                settings=settings,
                store=evidence_store,
                scan=scan,
                origin=EvidenceOrigin.BROKER,
                producer="policy_broker",
                content=b"x",
            )


class TestTrustClassification:
    def test_supervisor_evidence_is_trusted(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, _task = queued_scan
        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.SUPERVISOR,
            producer="supervisor",
            content=b"captured",
        )
        assert record.is_trusted

    def test_script_output_is_never_trusted(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        """§5.14: a script printing `confirmed=true` is not evidence."""
        scan, _task = queued_scan
        record = intake.record_untrusted_observation(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            producer="generated_script",
            content=b'{"confirmed": true}',
        )

        assert record.origin is EvidenceOrigin.UNTRUSTED_OBSERVATION
        assert not record.is_trusted

    def test_only_the_declared_origins_are_trusted(self) -> None:
        assert EvidenceOrigin.BROKER.is_trusted
        assert EvidenceOrigin.SUPERVISOR.is_trusted
        assert EvidenceOrigin.TLS_LANE.is_trusted
        assert not EvidenceOrigin.UNTRUSTED_OBSERVATION.is_trusted


class TestCapping:
    def test_content_over_the_cap_is_truncated_and_marked(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, _task = queued_scan
        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.BROKER,
            producer="broker",
            content=b"a" * 5000,
            max_bytes=1024,
        )

        assert record.truncated is True
        assert record.content_bytes == 1024

    def test_content_within_the_cap_is_untouched(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, _task = queued_scan
        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.BROKER,
            producer="broker",
            content=b"small",
            max_bytes=1024,
        )

        assert record.truncated is False
        assert evidence_store.get(record.content_ref) == b"small"


class TestRedaction:
    def test_secrets_are_redacted_before_storage(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        """Redact, then store — not store, then redact on read."""
        scan, _task = queued_scan
        body = b'{"api_key": "sk-abcdefghijklmnopqrstuvwxyz", "note": "keep me"}'

        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.BROKER,
            producer="broker",
            content=body,
        )

        stored = evidence_store.get(record.content_ref)
        assert b"sk-abcdefghijklmnopqrstuvwxyz" not in stored
        assert REDACTED.encode() in stored
        assert b"keep me" in stored
        assert record.redaction_state is RedactionState.REDACTED

    def test_a_sensitive_header_is_redacted_as_a_whole_value(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        """JSON artifacts are redacted structurally, so no fragment of the value survives.

        A text-only pass would leave `Path=/` and the cookie name behind, because it stops
        at the first delimiter inside the header value.
        """
        scan, _task = queued_scan
        body = json.dumps(
            {"status_code": 200, "headers": {"set-cookie": "sessionid=abc123; Path=/; Secure"}}
        ).encode()

        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.SUPERVISOR,
            producer="supervisor",
            content=body,
        )

        stored = json.loads(evidence_store.get(record.content_ref))
        assert stored["headers"]["set-cookie"] == REDACTED
        assert stored["status_code"] == 200
        assert record.redaction_state is RedactionState.REDACTED

    def test_clean_content_is_marked_clean(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, _task = queued_scan
        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.BROKER,
            producer="broker",
            content=b'{"status": 200}',
        )
        assert record.redaction_state is RedactionState.CLEAN

    def test_binary_content_carrying_a_secret_is_refused_rather_than_stored(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        """A binary artifact cannot be rewritten, so a secret inside one is refused."""
        scan, _task = queued_scan
        payload = b"\x89PNG\r\n\x1a\n" + b"Bearer abcdefghijklmnopqrstuvwxyz"

        with pytest.raises(intake.EvidenceIntakeError, match="credential-shaped"):
            intake.record_evidence(
                db_session,
                settings=settings,
                store=evidence_store,
                scan=scan,
                origin=EvidenceOrigin.BROKER,
                producer="broker",
                content=payload,
            )

    def test_ordinary_binary_content_is_stored(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, _task = queued_scan
        payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.BROKER,
            producer="broker",
            content=payload,
            suffix=".png",
        )
        assert evidence_store.get(record.content_ref) == payload


class TestIntegrity:
    def test_the_hash_covers_what_is_stored(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        """Hashing pre-redaction bytes would make verification fail against the artifact."""
        scan, _task = queued_scan
        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.BROKER,
            producer="broker",
            content=b'{"token": "sk-abcdefghijklmnopqrstuvwxyz"}',
        )

        assert intake.verify_integrity(evidence_store, record) is True

    def test_a_modified_artifact_fails_verification(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, _task = queued_scan
        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.BROKER,
            producer="broker",
            content=b"original",
        )

        evidence_store.put(record.content_ref, b"tampered")
        assert intake.verify_integrity(evidence_store, record) is False

    def test_a_missing_artifact_fails_verification(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, _task = queued_scan
        record = intake.record_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.BROKER,
            producer="broker",
            content=b"gone",
        )
        (evidence_store.root / record.content_ref).unlink()

        assert intake.verify_integrity(evidence_store, record) is False


class TestStoreSafety:
    def test_a_ref_cannot_escape_the_store_root(self, tmp_path) -> None:
        """A ref built from target-supplied text could otherwise overwrite another scan."""
        store = LocalDiskEvidenceStore(tmp_path / "evidence")
        with pytest.raises(EvidenceStoreError, match="escapes the store root"):
            store.put("../../etc/passwd", b"nope")

    def test_refs_are_built_from_internal_identifiers_only(self) -> None:
        ref = content_ref("scan-1", "task-1", "abc123", suffix=".json")
        assert ref == "scan-1/task-1/abc123.json"

    def test_a_ref_without_a_task_is_still_valid(self) -> None:
        assert content_ref("scan-1", None, "abc123") == "scan-1/scan/abc123.bin"

    def test_missing_content_raises(self, tmp_path) -> None:
        store = LocalDiskEvidenceStore(tmp_path)
        with pytest.raises(EvidenceStoreError, match="no evidence stored"):
            store.get("absent")


class TestJsonEvidence:
    def test_json_is_serialised_deterministically(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, _task = queued_scan
        first = intake.record_json_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.SUPERVISOR,
            producer="supervisor",
            payload={"b": 2, "a": 1},
        )
        second = intake.record_json_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.SUPERVISOR,
            producer="supervisor",
            payload={"a": 1, "b": 2},
        )

        assert first.content_hash == second.content_hash, "key order must not change the hash"


class TestListing:
    def test_evidence_is_listed_for_its_scan(
        self, db_session: Session, settings: Settings, evidence_store, queued_scan
    ) -> None:
        scan, _task = queued_scan
        for index in range(3):
            intake.record_evidence(
                db_session,
                settings=settings,
                store=evidence_store,
                scan=scan,
                origin=EvidenceOrigin.BROKER,
                producer="broker",
                content=f"item {index}".encode(),
            )

        records = intake.evidence_for_scan(db_session, scan.id)
        assert len(records) == 3
        assert all(r.is_trusted for r in records)


def test_retention_preserves_running_scan_then_expires_terminal_bytes(
    queued_scan, db_session, settings, authed_client
):
    from datetime import UTC, datetime, timedelta

    from scopelens.evidence.retention import prune
    from scopelens.persistence.models import EvidenceRow

    scan, task = queued_scan
    store = LocalDiskEvidenceStore(settings.evidence_store_path)
    record = intake.record_evidence(
        db_session,
        settings=settings,
        store=store,
        scan=scan,
        origin=EvidenceOrigin.SUPERVISOR,
        producer="reviewed",
        content=b"old evidence",
        task_id=task.id,
    )
    row = db_session.get(EvidenceRow, __import__("uuid").UUID(record.id))
    row.captured_at = datetime.now(UTC) - timedelta(days=31)
    db_session.commit()
    assert prune(settings, apply=True)["count"] == 0
    assert store.exists(record.content_ref)
    scan.status = "completed"
    db_session.commit()
    assert prune(settings)["count"] == 1 and store.exists(record.content_ref)
    assert (
        authed_client.get(f"/api/scans/{scan.id}/evidence/{record.id}/download").status_code == 410
    )
    assert prune(settings, apply=True)["count"] == 1
    assert not store.exists(record.content_ref)
    db_session.expire_all()
    assert db_session.get(EvidenceRow, row.id) is not None
