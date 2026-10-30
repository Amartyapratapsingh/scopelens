"""Offline scanner resource regression, run inside the trusted supervisor.

Usage: docker exec -i scopelens-dev-supervisor-1 python - < scripts/verify_scanner_resources.py
The disposable worker has network_mode=none and uses only synthetic fixture.invalid captures.
It inherits the deployed scanner image, memory cap and scratch limit. It never scans a URL.
"""

import json

import docker

from scopelens.config import Settings

settings = Settings()
client = docker.from_env()

code = r"""
import json,os,shutil
from types import SimpleNamespace
import scopelens.adapters.runner as runner
import time
os.environ['SCOPELENS_ZAP_TIMEOUT']='450'
original_zap=runner._run_zap
def measured_zap(*args,**kwargs):
 started=time.monotonic()
 result=original_zap(*args,**kwargs)
 print(json.dumps({'batch_seconds':round(time.monotonic()-started,2),'state':result.state,'error_summary':result.errors[:2],'memory_events':open('/sys/fs/cgroup/memory.events').read()}),flush=True)
 return result
runner._run_zap=measured_zap

from scopelens.adapters.runner import run_tools
from scopelens.domain.collection import CollectedResponse
rows=[CollectedResponse(url='https://fixture.invalid/page/'+str(i),route='/page/'+str(i),status=200,headers={'content-type':'text/html'},content_type='text/html',body_excerpt='<html><body>'+('a'*800000)+'</body></html>',body_bytes=800026,via_proxy=True) for i in range(110)]
def disk():
 u=shutil.disk_usage('/tmp');return {'total':u.total,'used':u.used,'free':u.free}
print(json.dumps({'before':disk()}),flush=True)
try:
 tools=run_tools(SimpleNamespace(origin='https://fixture.invalid'),SimpleNamespace(responses=rows))
 zap=next(tools)
 print(json.dumps({'tool':zap.tool,'state':zap.state,'errors':[e[-1200:] for e in zap.errors],'after_zap':disk()}),flush=True)
 # Check the next tool's ability to create its own temporary database, with networking disabled.
 import subprocess
 p=subprocess.run(['nuclei','-validate','-t','/app/tooling/nuclei-csp.yaml','-disable-update-check'],capture_output=True,text=True,timeout=20)
 print(json.dumps({'nuclei_exit':p.returncode,'diagnostic':(p.stdout+p.stderr)[-1000:],'after_nuclei':disk()}),flush=True)
 tools.close()
except Exception as e:
 print(json.dumps({'exception':type(e).__name__,'message':str(e),'disk':disk()}),flush=True)
print(json.dumps({'after_cleanup':disk()}),flush=True)
"""

container = client.containers.run(
    settings.kali_worker_image,
    ["python", "-c", code],
    network_mode="none",
    hostname="scopelens-fixture",
    extra_hosts={"scopelens-fixture": "127.0.0.1"},
    read_only=True,
    tmpfs={"/tmp": "rw,noexec,nosuid,size=256m"},
    mem_limit=f"{settings.scanner_worker_memory_limit_mb}m",
    nano_cpus=1000000000,
    pids_limit=512,
    cap_drop=["ALL"],
    security_opt=["no-new-privileges:true"],
    detach=True,
    environment={"HOME": "/tmp/tool-home", "PYTHONUNBUFFERED": "1"},
)
try:
    status = container.wait(timeout=510)
    output = container.logs().decode("utf-8", "replace")
    print(output)
    records = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    assert status["StatusCode"] == 0
    zap = next(row for row in records if row.get("tool") == "zap")
    assert zap["state"] == "completed" and not zap["errors"], zap
    assert zap["after_zap"]["used"] < 1024 * 1024
    assert next(row for row in records if "nuclei_exit" in row)["nuclei_exit"] == 0
    assert all("oom_kill 0" in row["memory_events"] for row in records if "memory_events" in row)
finally:
    container.remove(force=True)
