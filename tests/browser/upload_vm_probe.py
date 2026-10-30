"""Explicit disposable upload reproduction on the isolated worker VM, without egress."""

import argparse
import ast
import json
from pathlib import Path
from uuid import uuid4

from scripts.verify_worker_vm import remote_client

from scopelens.config import Settings
from scopelens.execution.supervisor import DockerWorkerSupervisor, WorkerSpec


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("bad", "fixed"), default="bad")
    parser.add_argument("--completion-timeout", action="store_true")
    args = parser.parse_args()
    tree = ast.parse(Path("tests/browser/test_expansion_browser_worker.py").read_text())
    setup = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "setup"
    )
    source = """import faulthandler,json,tempfile
from pathlib import Path
from http.server import ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace
from uuid import uuid4
from playwright.sync_api import sync_playwright
from playwright.sync_api import Locator, Page, Download
from pydantic import SecretStr
from scopelens.domain.assessment import AssessmentPlanVersion,DiscoveryCatalogue,RelatedOriginGrant
from scopelens.domain.browser_workflow import BrowserWorkflowRecipe
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import IdentityProfile,IdentityRequest,LoginRecipe,SessionProbe
from scopelens.domain.workflow import StateAssertion
from scopelens.expansion.browser_worker import collect_browser_assessments
from scopelens.workflows.cleanup import SQLiteCleanupJournal
"""
    source += (
        "\n"
        + Path("labs/expansion_browser/app.py").read_text().split('if __name__ == "__main__":')[0]
    )
    source += "\n" + ast.unparse(setup)
    # Load the current collector source into the isolated process to verify a fix
    # before rebuilding images. This is a diagnostic, not a deployed-image gate.
    workflow_source = Path("backend/scopelens/browser/workflow_checks.py").read_text()
    source += (
        "\nimport scopelens.browser.workflow_checks as workflow_module\n"
        "import scopelens.expansion.browser_worker as worker_module\n"
        f"exec({workflow_source!r}, workflow_module.__dict__)\n"
        "worker_module.run_browser_workflow=workflow_module.run_browser_workflow\n"
        f"variant={args.variant!r}\n"
        f"force_completion_timeout={args.completion_timeout!r}\n"
    )
    source += """
for cls,method in ((Locator,"click"),(Locator,"set_input_files"),(Page,"goto"),(Page,"close"),(Download,"cancel")):
 original=getattr(cls,method)
 def traced(self,*args,__old=original,__name=cls.__name__+"."+method,**kwargs):
  print("BEGIN",__name,flush=True)
  if __name=="Page.close" and force_completion_timeout:
   assert upload_body_pending, "response already complete; timeout case did not test unfinished close"
   print("PAGE_CLOSE_WHILE_UPLOAD_BODY_PENDING",flush=True)
  try:return __old(self,*args,**kwargs)
  finally:print("END",__name,flush=True)
 setattr(cls,method,traced)
records={"bad":"","fixed":""}
upload_headers=[]
upload_body_pending=[]
App=handler(records)
if force_completion_timeout:
 import time
 class Delayed(App):
  def end_headers(self):
   super().end_headers()
   if self.path.endswith("/upload"):
    upload_headers.append(True)
    upload_body_pending.append(True)
    print("UPLOAD_HEADERS_SENT_BODY_DELAYED",flush=True)
    time.sleep(5)
    upload_body_pending.pop()
 App=Delayed
 original_wait=Page.expect_request_finished
 def short_wait(self,predicate=None,**kwargs):
  return original_wait(self,predicate,timeout=500)
 Page.expect_request_finished=short_wait
server=ThreadingHTTPServer(("127.0.0.1",0),App)
Thread(target=server.serve_forever,daemon=True).start()
Path("/tmp/browser-home").mkdir(exist_ok=True)
with sync_playwright() as p, tempfile.TemporaryDirectory() as directory:
 browser=p.chromium.launch(headless=True,chromium_sandbox=True)
 origin=f"http://127.0.0.1:{server.server_port}"
 app=(origin,origin+"/foreign",browser,records)
 config,catalogue,plan,crawl,browser,control=setup(app,Path(directory),variant,"upload_serving")
 artifacts=[]
 def emit(kind,data):
  artifacts.append({"kind":kind,"data":data})
  print("CAPTURE",kind,data.get("kind",data.get("state","")),flush=True)
 faulthandler.dump_traceback_later(25)
 summary=collect_browser_assessments(config,catalogue,plan,browser,control,crawl,emit,owner="vm-diagnostic",token="fixture-token",cancelled=lambda:False)
 faulthandler.cancel_dump_traceback_later()
 print(json.dumps(summary),flush=True)
 result=next(a["data"] for a in artifacts if a["kind"]=="workflow_capture")
 print(json.dumps(result),flush=True)
 assert result["state"] == ("error" if force_completion_timeout else "confirmed" if variant == "bad" else "pass")
 assert result["cleanup_state"] == "clean" and records[variant] == ""
 if force_completion_timeout:assert upload_headers
 browser.close()
server.shutdown()
server.server_close()
"""
    image = json.loads(Path("runs/release/freeze.json").read_text())["images"][
        "SCOPELENS_BROWSER_WORKER_IMAGE"
    ]
    client = remote_client()
    client.images.get(image)  # Never try pulling an image during an offline diagnostic.
    supervisor = DockerWorkerSupervisor(Settings(), client=client)
    spec = WorkerSpec(
        image=image,
        command=["python", "-u", "-c", source],
        environment={},
        network="none",
        browser=True,
        max_runtime_seconds=65,
    )
    result = supervisor.run(spec, run_id="upload-diagnostic-" + uuid4().hex)
    print("SUCCEEDED", result.succeeded)
    print(result.stdout)
    print(result.stderr)
    if not result.succeeded:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
