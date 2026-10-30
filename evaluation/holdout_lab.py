"""Evaluator-host lifecycle commands for the isolated, opt-in holdout stack."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = [
    "docker",
    "compose",
    "-f",
    str(ROOT / "labs/holdout.compose.yml"),
    "--profile",
    "holdout",
]
STACK_LOCK = Path("/tmp/scopelens-stack.lock")
LOCK_HELPER = Path("/tmp/scopelens-with-lock.sh")
LOCK_TOKEN_ENV = "SCOPELENS_HOLDOUT_LOCK_TOKEN"


def has_helper_lock():
    token = os.environ.get(LOCK_TOKEN_ENV)
    return bool(
        token
        and (STACK_LOCK / "owner").exists()
        and (STACK_LOCK / "owner").read_text().strip() == token
    )


def locked_cli(module, arguments):
    """The shared helper owns acquisition, execution and release, including errors."""
    if not LOCK_HELPER.is_file():
        raise RuntimeError("Required shared stack lock helper is missing")
    subprocess.run(
        [
            str(LOCK_HELPER),
            "holdout-benchmark",
            "sh",
            "-c",
            'export SCOPELENS_HOLDOUT_LOCK_TOKEN="$(cat /tmp/scopelens-stack.lock/owner)"; exec "$@"',
            "holdout-helper",
            sys.executable,
            "-m",
            module,
            *arguments,
        ],
        check=True,
    )


@contextmanager
def stack_lock():
    # Never acquire or remove the shared lock here. This process must be the
    # command invoked by the mandatory shared helper, with its exact token.
    if not has_helper_lock():
        raise RuntimeError("Holdout operations require the shared stack lock helper")
    try:
        yield
    finally:
        if not has_helper_lock():
            raise RuntimeError("shared stack lock ownership changed during evaluation")


def command(*args, **kwargs):
    return subprocess.check_output([*COMPOSE, *args], text=True, **kwargs)


def seed():
    # Direct evaluator administration inside the private network. The gateway and
    # broker cannot access this installer. All credentials are synthetic lab values.
    script = """
import time, urllib.request, urllib.parse
url='http://wavsep:8080/wavsep/wavsep-install/install.jsp'
for attempt in range(90):
    try:
        urllib.request.urlopen(url, timeout=2)
        break
    except OSError:
        time.sleep(2)
else:
    raise RuntimeError('WAVSEP did not become ready')
body=urllib.parse.urlencode(dict(username='root',password='holdout-synthetic-local',
    host='database',port='3306',wavsep_username='',wavsep_password='')).encode()
text=urllib.request.urlopen(url,data=body,timeout=60).read().decode()
if 'Installation Successful' not in text and 'Installation Succeeded' not in text:
    # The behavior oracle remains the final admission check. Retain the installer
    # receipt rather than infer success solely from HTTP 200.
    print(text)
else:
    print('installer completed')
"""
    result = command("exec", "-T", "labs-holdout-b", "python", "-c", script)
    # Upstream installer creates user@database, while the application connects from
    # its own container. Grant only SELECT to the remote synthetic fixture account.
    sql = "CREATE USER IF NOT EXISTS 'wavsep'@'%' IDENTIFIED BY 'wavsepPass782'; GRANT SELECT ON wavsepDB.* TO 'wavsep'@'%'; FLUSH PRIVILEGES;"
    command("exec", "-T", "database", "mariadb", "-uroot", "-pholdout-synthetic-local", "-e", sql)
    return result


def build():
    lock = json.loads((ROOT / "evaluation/holdout/source-lock.json").read_text())
    sources = ROOT / "runs/holdout-benchmark/sources"
    sources.mkdir(parents=True, exist_ok=True)
    for project in ["vulnerableapp", "wavsep", "benchmarkjava"]:
        target = sources / project
        if not target.exists():
            subprocess.run(
                ["git", "clone", "--no-checkout", lock[project]["url"], str(target)], check=True
            )
            subprocess.run(
                ["git", "-C", str(target), "checkout", "--detach", lock[project]["revision"]],
                check=True,
            )
        commit = subprocess.check_output(
            ["git", "-C", str(target), "rev-parse", "HEAD"], text=True
        ).strip()
        if commit != lock[project]["revision"]:
            raise RuntimeError(f"{project} differs from the pinned source")
        dirty = subprocess.check_output(
            ["git", "-C", str(target), "diff", "--name-only", "HEAD"], text=True
        ).strip()
        if dirty:
            raise RuntimeError(f"{project} tracked source changed")
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            str(sources / "vulnerableapp") + ":/source",
            "-w",
            "/source",
            lock["images"]["builder"],
            "gradle",
            "--no-daemon",
            "bootJar",
        ],
        check=True,
    )
    subprocess.run(
        ["mvn", "-q", "-f", str(sources / "wavsep/pom.xml"), "clean", "package"], check=True
    )
    subprocess.run(
        ["mvn", "-q", "-f", str(sources / "benchmarkjava/pom.xml"), "-DskipTests", "package"],
        check=True,
    )
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [
            sources / "vulnerableapp/build/libs/VulnerableApp-1.0.0.jar",
            sources / "wavsep/target/wavsep.war",
            sources / "benchmarkjava/target/benchmark.war",
        ]
    }


def reset():
    # Recreate only this stack's containers. No shared volumes or other labs are
    # deleted. In-memory H2/SQLite and tmpfs MariaDB seed afresh; Tomcat's writable
    # layer with its Derby configuration is replaced with the container.
    command(
        "up",
        "-d",
        "--force-recreate",
        "database",
        "wavsep",
        "vulnerableapp",
        "private-fixture",
        "labs-holdout-a",
        "labs-holdout-b",
        "labs-holdout-c",
        "labs-holdout-d",
        "benchmarkjava",
    )
    command("up", "-d", "--wait", "database")
    return seed()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["build", "reset", "seed"])
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if not has_helper_lock():
        if os.environ.get(LOCK_TOKEN_ENV):
            raise RuntimeError("Inherited helper ownership token is invalid")
        locked_cli("evaluation.holdout_lab", sys.argv[1:])
        return
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with stack_lock():
        result = {"build": build, "reset": reset, "seed": seed}[args.action]()
    with args.receipt.open("x") as stream:
        os.chmod(args.receipt, 0o600)
        json.dump({"action": args.action, "receipt": result}, stream, indent=2)


if __name__ == "__main__":
    main()
