"""Measure the dedicated worker deployment, including direct egress and process stop."""

import json
import ssl
import subprocess
import threading
import time
import urllib.request
import uuid
from pathlib import Path

import docker

from scopelens.config import Settings
from scopelens.execution.supervisor import DockerWorkerSupervisor, WorkerSpec


def remote_client():
    certs = Path("runs/worker-vm/client").resolve()
    return docker.DockerClient(
        base_url="tcp://127.0.0.1:23976",
        tls=docker.tls.TLSConfig(
            client_cert=(str(certs / "cert.pem"), str(certs / "key.pem")),
            ca_cert=str(certs / "ca.pem"),
            verify=True,
        ),
        timeout=35,
    )


def main():
    client = remote_client()
    info = client.info()
    assert info["Name"] == "lima-scopelens-workers", info["Name"]
    assert info["ServerVersion"] == "29.1.3", "qualify a changed Docker engine before activation"
    assert info["ID"] != docker.from_env().info()["ID"], "worker daemon shares control VM"
    vm = json.loads(subprocess.check_output(["limactl", "list", "scopelens-workers", "--json"]))
    import yaml

    config = yaml.safe_load((Path(vm["dir"]) / "lima.yaml").read_text())
    assert config["mounts"] == [] and not config["ssh"]["forwardAgent"]
    boot = subprocess.check_output(
        ["limactl", "shell", "scopelens-workers", "--", "cat", "/proc/cmdline"], text=True
    )
    assert "arm64.nosme" in boot.split(), "apply the measured ARM browser compatibility setting"
    context = ssl.create_default_context(cafile="runs/worker-vm/client/ca.pem")
    try:
        urllib.request.urlopen("https://127.0.0.1:23976/_ping", context=context, timeout=3)
    except (OSError, ssl.SSLError):
        pass
    else:
        raise AssertionError("Docker API accepted a caller without a client certificate")
    freeze = json.loads(Path("runs/release/freeze.json").read_text())
    image = freeze["images"]["SCOPELENS_TOOL_WORKER_IMAGE"]
    supervisor = DockerWorkerSupervisor(Settings(), client=client)
    source = """import socket,json,os,urllib.request
results={}
for host,port in [('1.1.1.1',443),('169.254.169.254',80),('192.168.5.2',8090),('192.168.5.2',5433),('172.30.0.1',2376),('172.28.0.10',80)]:
 try:
  with socket.create_connection((host,port),timeout=.4):results[f'{host}:{port}']='CONNECTED'
 except OSError:results[f'{host}:{port}']='blocked'
for path in ['/var/run/docker.sock','/worker-docker-certs/key.pem','/Users','/tmp/other-scan-marker']:
 results[path]=os.path.exists(path)
try:
 with socket.create_connection(('proxy',8080),timeout=5) as sock:
  sock.sendall(b'GET http://example.invalid/ HTTP/1.1\\r\\nHost: example.invalid\\r\\nConnection: close\\r\\n\\r\\n')
  results['proxy_status']=sock.recv(512).decode().split('\\r\\n')[0]
except OSError as exc:results['proxy_status']=type(exc).__name__
print(json.dumps(results))
"""
    spec = WorkerSpec(
        image=image,
        command=["python", "-c", source],
        environment={},
        network="scopelens_worker_net",
        max_runtime_seconds=20,
    )
    result = supervisor.run(spec, run_id="boundary-" + uuid.uuid4().hex)
    assert result.succeeded, result.stderr
    observations = json.loads(result.stdout)
    assert "CONNECTED" not in observations.values(), observations
    assert all(not value for key, value in observations.items() if key.startswith("/")), (
        observations
    )
    assert "403" in observations["proxy_status"], observations
    holder_spec = WorkerSpec(
        image=image,
        command=[
            "python",
            "-u",
            "-c",
            "import socket,time;open('/tmp/other-scan-marker','w').write('private');s=socket.socket();s.bind(('0.0.0.0',8001));s.listen();print('READY');time.sleep(30)",
        ],
        environment={},
        network="scopelens_worker_net",
    )
    holder = client.containers.run(**supervisor._container_kwargs(holder_spec))
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and b"READY" not in holder.logs():
            time.sleep(0.1)
        assert b"READY" in holder.logs(), "cross-scan canary must actually listen"
        holder.reload()
        address = holder.attrs["NetworkSettings"]["Networks"]["scopelens_worker_net"]["IPAddress"]
        cross_source = f"""import socket,os,json
out={{'other_file':os.path.exists('/tmp/other-scan-marker')}}
try:
 socket.create_connection(({address!r},8001),timeout=.5);out['peer']='CONNECTED'
except OSError:out['peer']='blocked'
print(json.dumps(out))
"""
        cross = supervisor.run(
            WorkerSpec(
                image,
                ["python", "-c", cross_source],
                {},
                "scopelens_worker_net",
                max_runtime_seconds=5,
            ),
            run_id="cross-" + uuid.uuid4().hex,
        )
        assert cross.succeeded and json.loads(cross.stdout) == {
            "other_file": False,
            "peer": "blocked",
        }, cross.stdout
    finally:
        holder.remove(force=True)
    scan_id = uuid.uuid4()
    sleeper = WorkerSpec(
        image=image,
        command=["python", "-c", "import time;time.sleep(60)"],
        environment={},
        network="scopelens_worker_net",
        labels={"scopelens.scan_id": str(scan_id)},
        max_runtime_seconds=65,
    )
    captured = []
    thread = threading.Thread(
        target=lambda: captured.append(supervisor.run(sleeper, run_id="stop-" + scan_id.hex))
    )
    thread.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if client.containers.list(filters={"label": "scopelens.scan_id=" + str(scan_id)}):
            break
        time.sleep(0.1)
    else:
        raise AssertionError("test worker did not start")
    started = time.monotonic()
    assert supervisor.stop_all_for_scan(scan_id) == 1
    thread.join(timeout=30)
    stop_seconds = time.monotonic() - started
    assert not thread.is_alive() and stop_seconds < 30 and captured
    report = {
        "vm": info["Name"],
        "docker_version": info["ServerVersion"],
        "daemon_separate_from_control": True,
        "host_mounts": [],
        "client_certificate_required": True,
        "cross_scan_files_and_connection_blocked": True,
        "observations": observations,
        "worker_stop_seconds": stop_seconds,
        "freeze": freeze,
        "qualification": "boundary probes passed; full API/browser report journey required separately",
    }
    Path("runs/worker-vm/boundary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Dedicated worker VM: authenticated control, isolated files, direct egress denial, enforcing proxy and cancellation passed"
    )


if __name__ == "__main__":
    main()
