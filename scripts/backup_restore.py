"""Encrypted operational backup and non-destructive restore into a new database."""

import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from cryptography.fernet import Fernet

from scopelens.config import Settings

COMPOSE = ["docker", "compose", "--env-file", ".env", "-f", "deploy/docker-compose.dev.yml"]


def command(args, *, content=None):
    return subprocess.run([*COMPOSE, *args], input=content, capture_output=True, check=True).stdout


def backup(destination):
    settings = Settings()
    if not settings.evidence_encryption_key:
        raise ValueError("Configure the encryption key before backup")
    if destination.exists():
        raise ValueError("Backup destination already exists")
    # The snapshot includes rows only after their content-addressed files were stored.
    # A retention lock protects those immutable objects while the archive is collected.
    with psycopg.connect(
        settings.database_url.replace("postgresql+psycopg://", "postgresql://")
    ) as conn:
        conn.execute("SELECT pg_advisory_lock(412509)")
        conn.commit()
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        snapshot = conn.execute("SELECT pg_export_snapshot()").fetchone()[0]
        dump = command(
            [
                "exec",
                "-T",
                "postgres",
                "pg_dump",
                "-U",
                "scopelens",
                "-d",
                "scopelens",
                "--format=custom",
                "--no-owner",
                "--snapshot=" + snapshot,
            ]
        )
        evidence = command(
            ["exec", "-T", "supervisor", "tar", "-czf", "-", "-C", "/app/runs/evidence", "."]
        )
        counts = {
            name: conn.execute("SELECT count(*) FROM " + name).fetchone()[0]
            for name in ["scans", "findings", "evidence", "audit_events"]
        }
    files = {"database.dump": dump, "evidence.tar.gz": evidence}
    manifest = {
        "version": "backup-v1",
        "created": datetime.now(UTC).isoformat(),
        "counts": counts,
        "sha256": {name: hashlib.sha256(content).hexdigest() for name, content in files.items()},
    }
    files["manifest.json"] = json.dumps(manifest).encode()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(content))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(
        Fernet(settings.evidence_encryption_key.get_secret_value().encode()).encrypt(
            archive.getvalue()
        )
    )
    destination.chmod(0o600)
    return {"backup": str(destination), "counts": counts, "encrypted": True}


def restore(source, database, evidence_dir):
    if not re.fullmatch(r"scopelens_restore_[a-z0-9_]{1,40}", database):
        raise ValueError("Restore requires a new scopelens_restore_* database")
    if evidence_dir.exists():
        raise ValueError("Evidence destination must not already exist")
    settings = Settings()
    raw = Fernet(settings.evidence_encryption_key.get_secret_value().encode()).decrypt(
        source.read_bytes()
    )
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        if {m.name for m in archive.getmembers()} != {
            "database.dump",
            "evidence.tar.gz",
            "manifest.json",
        }:
            raise ValueError("Unexpected backup contents")
        files = {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}
    manifest = json.loads(files["manifest.json"])
    for name, digest in manifest["sha256"].items():
        if hashlib.sha256(files[name]).hexdigest() != digest:
            raise ValueError("Backup integrity mismatch")
    # createdb fails on an existing database. There is deliberately no --clean or drop.
    command(["exec", "-T", "postgres", "createdb", "-U", "scopelens", database])
    command(
        [
            "exec",
            "-T",
            "postgres",
            "pg_restore",
            "-U",
            "scopelens",
            "-d",
            database,
            "--no-owner",
            "--single-transaction",
        ],
        content=files["database.dump"],
    )
    with tarfile.open(fileobj=io.BytesIO(files["evidence.tar.gz"]), mode="r:gz") as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk():
                raise ValueError("Link in evidence backup")
        archive.extractall(evidence_dir, filter="data")
    conn_url = (
        settings.database_url.replace("postgresql+psycopg://", "postgresql://").rsplit("/", 1)[0]
        + "/"
        + database
    )
    with psycopg.connect(conn_url) as conn:
        counts = {
            name: conn.execute("SELECT count(*) FROM " + name).fetchone()[0]
            for name in manifest["counts"]
        }
        assert counts == manifest["counts"], "Restored row counts differ"
    return {
        "restored_database": database,
        "evidence_directory": str(evidence_dir),
        "counts": counts,
        "execution_started": False,
    }


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("backup")
    p.add_argument("destination", type=Path)
    p = sub.add_parser("restore")
    p.add_argument("source", type=Path)
    p.add_argument("--database", required=True)
    p.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    result = (
        backup(args.destination)
        if args.command == "backup"
        else restore(args.source, args.database, args.evidence_dir)
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
