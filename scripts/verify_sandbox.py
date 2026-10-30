"""Real dedicated-VM execution, containment, output caps and deadline checks."""

import json
import uuid
from pathlib import Path

from scopelens.execution.sandbox import ScriptRequest, execute


def run(source, language="python"):
    return execute(
        ScriptRequest(
            scan_id=uuid.uuid4(), source=source, language=language, artifacts={"sample": 1}
        )
    )


def main():
    result = run(
        'import json,sys; a=json.load(sys.stdin); print(json.dumps({"keys":list(a),"confirmed":True}))'
    )
    assert result["state"] == "completed" and result["trusted"] is False
    assert json.loads(result["stdout"])["keys"] == ["sample"]
    isolation = run("""import json,os,socket
out={}
for path in ['/Users/adityapratapsingh/.env','/var/run/docker.sock','/home','/proc/1/environ']:
 try:
  open(path).read();out[path]='readable'
 except Exception as e:out[path]=type(e).__name__
try:
 socket.create_connection(('1.1.1.1',443),timeout=.2);out['network']='connected'
except Exception as e:out['network']=type(e).__name__
print(json.dumps(out))""")
    assert "readable" not in isolation["stdout"] and "connected" not in isolation["stdout"]
    bash = run('printf "bounded bash\\n"', "bash")
    assert bash["state"] == "completed" and "bounded bash" in bash["stdout"]
    flood = run('while True: print("x"*8192,flush=True)')
    assert flood["state"] == "limited" and len(flood["stdout"]) <= 65536
    timeout = run("import time; time.sleep(60)")
    assert timeout["state"] != "completed" and timeout["duration_seconds"] < 30
    ignored_input = execute(
        ScriptRequest(
            scan_id=uuid.uuid4(),
            language="python",
            source="print('done')",
            artifacts={"large": "x" * 900000},
        )
    )
    assert ignored_input["state"] == "completed" and ignored_input["duration_seconds"] < 20
    report = {
        "ignored_large_input": ignored_input,
        "local_analysis": result,
        "isolation": isolation,
        "bash": bash,
        "output_limit": {k: v for k, v in flood.items() if k not in {"stdout", "stderr"}},
        "deadline": timeout,
    }
    path = Path("runs/m4-verification/sandbox.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print("Dedicated VM containment, bounded Python/Bash, output cap and deadline passed")


if __name__ == "__main__":
    main()
