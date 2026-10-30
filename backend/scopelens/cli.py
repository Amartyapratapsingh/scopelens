"""Command-line entry point.

Used both by the compose stack (``migrate``, ``seed-operator``) and by the operator
directly. Kept deliberately small: this is an operational tool, not a second interface
to the product.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from scopelens.config import REPO_ROOT, get_settings
from scopelens.manifest import write_manifest
from scopelens.security.passwords import PasswordError, hash_password


def _alembic_config():  # type: ignore[no-untyped-def]
    from alembic.config import Config

    ini = REPO_ROOT / "alembic.ini"
    if not ini.exists():
        raise SystemExit(f"error: {ini} not found; cannot run migrations")
    config = Config(str(ini))
    # Absolute, so the command behaves the same from any working directory.
    config.set_main_option(
        "script_location", str(REPO_ROOT / "backend" / "scopelens" / "persistence" / "migrations")
    )
    return config


def cmd_migrate(_: argparse.Namespace) -> int:
    from alembic import command

    command.upgrade(_alembic_config(), "head")
    print("migrations: database is at head")
    return 0


def cmd_seed_operator(_: argparse.Namespace) -> int:
    """Create or refresh the single operator account from the environment.

    There is no signup path, by design (Build Plan §5.1). If no credential is
    configured this fails loudly rather than creating a default account.
    """
    from scopelens.persistence.repositories import record_audit, upsert_operator
    from scopelens.persistence.session import session_scope

    settings = get_settings()

    if settings.operator_password_hash is not None:
        password_hash = settings.operator_password_hash.get_secret_value()
    elif settings.operator_password is not None:
        try:
            password_hash = hash_password(settings.operator_password.get_secret_value())
        except PasswordError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    else:
        print(
            "error: no operator credential configured. Set SCOPELENS_OPERATOR_PASSWORD "
            "or SCOPELENS_OPERATOR_PASSWORD_HASH in .env (run `make init-env` to generate "
            "one). Refusing to create an account with a default password.",
            file=sys.stderr,
        )
        return 1

    with session_scope(settings) as session:
        row, created = upsert_operator(
            session,
            username=settings.operator_username,
            password_hash=password_hash,
        )
        record_audit(
            session,
            actor="cli",
            action="operator.seed",
            subject_type="operator",
            subject_id=str(row.id),
            outcome="created" if created else "refreshed",
            detail={"username": row.username},
        )
        username = row.username

    verb = "created" if created else "refreshed"
    print(f"operator: {verb} account {username!r} (no signup path exists)")
    return 0


def cmd_hash_password(_: argparse.Namespace) -> int:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm:  ")
    if password != confirm:
        print("error: passwords do not match", file=sys.stderr)
        return 1
    try:
        digest = hash_password(password)
    except PasswordError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(digest)
    print(
        "\nSet SCOPELENS_OPERATOR_PASSWORD_HASH to this value. It contains `$`, so if "
        "you use it through Docker Compose interpolation you must escape each `$` as "
        "`$$`. Setting SCOPELENS_OPERATOR_PASSWORD instead avoids that entirely.",
        file=sys.stderr,
    )
    return 0


def cmd_check_registry(_: argparse.Namespace) -> int:
    from scopelens.domain.registry import RegistryError, load_registry

    settings = get_settings()
    try:
        registry = load_registry(settings.checks_registry_dir)
    except RegistryError as exc:
        print(f"registry: INVALID\n{exc}", file=sys.stderr)
        return 1

    print(f"registry: ok ({len(registry.entries)} entries)")
    supported = [e for e in registry.entries if e.is_supported]
    print(f"supported (review_state=enabled): {len(supported)}")
    for entry in registry.entries:
        flag = "supported" if entry.is_supported else entry.review_state.value
        print(
            f"  {entry.id:<24} {entry.category.value}  {entry.availability.stance:<8} "
            f"{entry.availability.phase:<3} [{flag}]"
        )
    return 0


def cmd_manifest(_: argparse.Namespace) -> int:
    from scopelens.persistence.session import session_scope

    settings = get_settings()
    try:
        with session_scope(settings) as session:
            path = write_manifest(settings, session)
    except Exception as exc:  # noqa: BLE001 - the manifest must still be writable offline
        print(f"manifest: database unavailable ({exc.__class__.__name__}); schema unrecorded")
        path = write_manifest(settings, None)
    print(f"manifest: wrote {path}")
    return 0


def cmd_dispatch(args: argparse.Namespace) -> int:
    """Poll the outbox and enqueue work to Celery.

    Reconciles unsent rows first: a crash between writing the outbox row and enqueuing it
    is the normal case the outbox exists to handle, not an exceptional one.
    """
    from scopelens.dispatch import dispatch_forever, dispatch_once

    settings = get_settings()
    if args.once:
        result = dispatch_once(settings)
        print(
            f"dispatch: examined {result.examined}, enqueued {result.enqueued}, "
            f"failed {result.failed}, skipped {result.skipped}"
        )
        return 0 if result.failed == 0 else 1

    dispatch_forever(settings, interval_seconds=args.interval)
    return 0


def cmd_reconcile(_: argparse.Namespace) -> int:
    """Reconcile orphans, stale leases and lost outcomes."""
    from scopelens.execution.reconciler import reconcile

    report = reconcile(get_settings())
    print(report.render())
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "scopelens.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scopelens",
        description="ScopeLens operator tooling.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("migrate", help="apply database migrations to head").set_defaults(
        func=cmd_migrate
    )
    sub.add_parser(
        "seed-operator", help="create or refresh the single operator account"
    ).set_defaults(func=cmd_seed_operator)
    sub.add_parser("hash-password", help="generate a bcrypt hash for the operator").set_defaults(
        func=cmd_hash_password
    )
    sub.add_parser("check-registry", help="validate the check registry").set_defaults(
        func=cmd_check_registry
    )
    sub.add_parser("manifest", help="regenerate the release manifest").set_defaults(
        func=cmd_manifest
    )
    sub.add_parser(
        "reconcile", help="reconcile orphans, stale leases and lost outcomes"
    ).set_defaults(func=cmd_reconcile)

    dispatch = sub.add_parser("dispatch", help="poll the outbox and enqueue work")
    dispatch.add_argument("--once", action="store_true", help="drain once and exit")
    dispatch.add_argument("--interval", type=float, default=1.0, help="poll interval in seconds")
    dispatch.set_defaults(func=cmd_dispatch)

    serve = sub.add_parser("serve", help="run the API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    serve.add_argument("--log-level", default="info")
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
