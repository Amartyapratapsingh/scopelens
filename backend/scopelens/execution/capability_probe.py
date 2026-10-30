"""Supervisor-owned, offline measurements of configured immutable worker images.

This command is deliberately separate from ordinary worker stdout. The supervisor
resolves each image to a local content ID, starts that ID without a network or mounts,
and accepts only the fixed probe's bounded JSON result.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import suppress
from datetime import UTC, datetime

from scopelens.domain.capabilities import canonical_sha256, plan_bindings
from scopelens.domain.report_metadata import CapabilitySnapshot, ImageBinding, MeasuredTool

PROBE_SOURCE = r"""
import hashlib, importlib.metadata, json, os, pathlib, re, subprocess

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def binary(name, path, args):
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        return {'name': name, 'state': 'absent'}
    try:
        result = subprocess.run([path, *args], stdin=subprocess.DEVNULL,
            capture_output=True, timeout=10, env={'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': '/tmp', 'LC_ALL': 'C'})
        output = (result.stdout + b'\n' + result.stderr)[:8192].decode('utf-8', 'replace')
        output = re.sub(r'\x1b\[[0-9;]*m', '', output)
        line = next((line.strip() for line in output.splitlines()
                     if re.search(r'\d+\.\d+(?:\.\d+)?', line)
                     and (name.lower() in line.lower() or
                          (name == 'zap' and re.fullmatch(r'\s*\d+\.\d+\.\d+\s*', line)) or
                          (name == 'chromium' and re.fullmatch(
                              r'Google Chrome for Testing \d+\.\d+\.\d+\.\d+\s*', line)))), '')
        if result.returncode != 0 or not line:
            return {'name': name, 'state': 'failed'}
        return {'name': name, 'state': 'present', 'version': line[:160], 'sha256': digest(path)}
    except (OSError, subprocess.TimeoutExpired):
        return {'name': name, 'state': 'failed'}

def package(name):
    try:
        version = importlib.metadata.version(name)
        dist = importlib.metadata.distribution(name)
        path = str(dist.locate_file('playwright/__init__.py'))
        return {'name': name, 'state': 'present', 'version': version, 'sha256': digest(path)}
    except (OSError, ImportError, importlib.metadata.PackageNotFoundError):
        return {'name': name, 'state': 'absent'}

role = __import__('sys').argv[1]
if role == 'kali':
    results = [binary('zap', '/opt/zap/zap.sh', ['-Xmx128m', '-dir', '/tmp/zap-probe', '-version']),
               binary('nuclei', '/usr/local/bin/nuclei', ['-version']),
               binary('testssl', '/opt/testssl/testssl.sh', ['--version'])]
elif role == 'tool':
    results = []
elif role == 'browser':
    results = [package('playwright')]
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            path = playwright.chromium.executable_path
        results.append(binary('chromium', path, ['--version']))
    except Exception:
        results.append({'name': 'chromium', 'state': 'failed'})
else:
    raise SystemExit(2)
root = pathlib.Path('/app/backend')
sources = [str(p.relative_to(root)) + ':' + digest(p)
           for p in sorted(root.rglob('*.py')) if '__pycache__' not in p.parts]
source_sha256 = hashlib.sha256('\n'.join(sources).encode()).hexdigest() if sources else None
print(json.dumps({'version': 'runtime-probe-v2', 'role': role, 'tools': results,
                  'source_sha256': source_sha256}, separators=(',', ':')))
"""

PROBE_SHA256 = hashlib.sha256(PROBE_SOURCE.encode()).hexdigest()
MAX_OUTPUT_BYTES = 12_000


class ProbeFailure(RuntimeError):
    """A probe failed; installation inventory must remain unknown."""


def _run_image_probe(client, role: str, image_ref: str) -> tuple[ImageBinding, list[dict], str]:
    if role not in {"tool", "kali", "browser"}:
        raise ValueError("unsupported image role")
    image = client.images.get(image_ref)
    image_id = image.id
    architecture = image.attrs.get("Architecture", "")
    if not image_id.startswith("sha256:") or len(image_id) != 71 or not architecture:
        raise ProbeFailure("image identity or architecture unavailable")
    binding = ImageBinding(
        role=role, image_id=image_id, architecture=architecture, probe_sha256=PROBE_SHA256
    )
    container = client.containers.run(
        image=image_id,
        command=["python", "-I", "-c", PROBE_SOURCE, role],
        detach=True,
        network_mode="none",
        environment={"PATH": "/app/.venv/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp"},
        read_only=True,
        tmpfs={"/tmp": "rw,noexec,nosuid,size=16m"},
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        privileged=False,
        mem_limit="512m",
        nano_cpus=500_000_000,
        pids_limit=64,
        auto_remove=False,
    )
    try:
        try:
            status = container.wait(timeout=45)
        except Exception as exc:
            container.kill()
            raise ProbeFailure("image probe timed out or could not be observed") from exc
        container.reload()
        if container.image.id != image_id or status.get("StatusCode") != 0:
            raise ProbeFailure("image identity or probe exit mismatch")
        output = bytearray()
        chunks = container.logs(stdout=True, stderr=False, stream=True)
        try:
            for chunk in chunks:
                output.extend(chunk)
                if len(output) > MAX_OUTPUT_BYTES:
                    raise ProbeFailure("probe output exceeds limit")
        finally:
            with suppress(AttributeError):
                chunks.close()
        if len(output.splitlines()) != 1:
            raise ProbeFailure("probe output is not one JSON line")
        try:
            payload = json.loads(output)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ProbeFailure("probe output is not JSON") from exc
        expected = {
            "kali": {"zap", "nuclei", "testssl"},
            "tool": set(),
            "browser": {"playwright", "chromium"},
        }[role]
        if (
            not isinstance(payload, dict)
            or set(payload) != {"version", "role", "tools", "source_sha256"}
            or payload["version"] != "runtime-probe-v2"
            or not isinstance(payload["source_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", payload["source_sha256"]) is None
            or payload["role"] != role
            or not isinstance(payload["tools"], list)
            or {item.get("name") for item in payload["tools"] if isinstance(item, dict)} != expected
            or len(payload["tools"]) != len(expected)
        ):
            raise ProbeFailure("probe inventory is malformed")
        for item in payload["tools"]:
            if item.get("state") not in {"present", "absent", "failed"}:
                raise ProbeFailure("invalid probe state")
            if item["state"] == "present" and (
                set(item) != {"name", "state", "version", "sha256"}
                or not isinstance(item.get("version"), str)
                or not item["version"]
                or not isinstance(item.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
            ):
                raise ProbeFailure("invalid tool measurement")
            if item["state"] != "present" and set(item) != {"name", "state"}:
                raise ProbeFailure("invalid absent or failed measurement")
        return binding, payload["tools"], payload["source_sha256"]
    finally:
        with suppress(Exception):  # Docker cleanup must not mask the measurement failure.
            container.remove(force=True)


def collect_runtime_measurement(client, *, image_refs: dict[str, str]) -> dict:
    """Measure each configured image. Failed probes never become an empty inventory."""
    bindings = []
    tools = []
    sources = []
    complete = True
    for role, ref in sorted(image_refs.items()):
        try:
            image = client.images.get(ref)
            expected = ImageBinding(
                role=role,
                image_id=image.id,
                architecture=image.attrs["Architecture"],
                probe_sha256=PROBE_SHA256,
            ).model_dump(mode="json")
            bindings.append(expected)
            binding, rows, source = _run_image_probe(client, role, ref)
            if binding.model_dump(mode="json") != expected:
                raise ProbeFailure("image changed during probe")
            sources.append(source)
        except Exception:  # noqa: BLE001 - Docker failures mean unknown, not absence.
            complete = False
            continue
        for row in rows:
            if row["state"] == "failed":
                complete = False
            elif row["state"] == "present":
                tools.append(
                    MeasuredTool(
                        name=row["name"],
                        measured_version=row["version"],
                        binary_sha256=row["sha256"],
                        image_id=binding.image_id,
                        verification_ref=f"probe:{binding.image_id}:{PROBE_SHA256}:{row['name']}",
                    ).model_dump(mode="json")
                )
    return {
        "image_bindings": bindings,
        "installed_tools": tools,
        "installation_complete": complete and len(bindings) == len(image_refs),
        "source_sha256": sources[0]
        if len(sources) == len(image_refs) and len(set(sources)) == 1
        else None,
    }


def build_capability_snapshot(
    plan: dict,
    *,
    scan_id: str,
    scope_version_id: str,
    profile: str,
    measurement: dict,
    runtime_controls: list[dict],
) -> dict:
    """Bind observed inventory and per-control decisions to one frozen scan plan.

    Caller must supply trusted implementation, prerequisite and authority decisions for
    every enabled profile control. Missing decisions keep executable total unknown.
    """
    from scopelens.domain.enums import ProfileName
    from scopelens.domain.registry import CheckRegistry

    bindings = plan_bindings(
        plan, scan_id=scan_id, scope_version_id=scope_version_id, profile=profile
    )
    registry = CheckRegistry.model_validate(plan["registry"])
    enabled = {
        entry.id for entry in registry.for_profile(ProfileName(profile)) if entry.is_supported
    }
    measured_ids = {item.get("control_id") for item in runtime_controls}
    valid_controls = len(runtime_controls) == len(measured_ids) and measured_ids == enabled
    candidate = bindings["candidate_fingerprint"]
    if (
        len(candidate) != 64
        or not measurement["image_bindings"]
        or measurement["image_bindings"] != plan.get("capability_expected_images")
    ):
        raise ProbeFailure("candidate or image binding unavailable")
    snapshot = CapabilitySnapshot(
        version="capability-snapshot-v2",
        **bindings,
        source_sha256=candidate,
        verification_ref=f"runtime:{canonical_sha256(measurement)}",
        measured_at=datetime.now(UTC).isoformat(),
        image_bindings=measurement["image_bindings"],
        installation_complete=measurement["installation_complete"],
        runtime_inventory_complete=valid_controls,
        installed_tools=measurement["installed_tools"],
        runtime_controls=runtime_controls,
    )
    return snapshot.model_dump(mode="json")
