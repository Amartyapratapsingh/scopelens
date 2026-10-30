"""Local parser-delay regression using the deployed browser worker, without target traffic.

Run inside the trusted supervisor. The disposable VM worker uses network_mode=none;
its only server is a synthetic HTTP fixture on its own loopback interface.
"""

import json

import docker

from scopelens.config import Settings

CODE = r"""
import contextlib,io,json,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from playwright.sync_api import sync_playwright
from scopelens.browser.worker import Controller
from scopelens.browser.policy import BrowserAction
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path=='/slow.js':
   time.sleep(15);body=b'window.fixtureLoaded=true';content_type='application/javascript'
  else:
   body=b'<html><head><script src="/slow.js"></script></head><body><button>View details</button></body></html>';content_type='text/html'
  self.send_response(200);self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(body)));self.end_headers()
  with contextlib.suppress(BrokenPipeError):self.wfile.write(body)
 def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True,chromium_sandbox=True)
 page=browser.new_page()
 controller=Controller.__new__(Controller)
 controller.sequence=0;controller.gaps=[];controller.states=[];controller.context_id='local-fixture'
 commands=[]
 controller.command=lambda operation,**fields:commands.append({'operation':operation,**fields})
 url='http://127.0.0.1:'+str(server.server_port)+'/'
 started=time.monotonic()
 try:
  with contextlib.redirect_stdout(io.StringIO()):
   controller.act(page,BrowserAction(kind='navigate',url=url),lambda:page.goto(url,wait_until='commit'))
  assert controller.states and 'View details' in controller.states[0]['text']
  assert commands[-1]['operation']=='complete' and commands[-1]['result']=='succeeded'
  result={'result':'captured','states':len(controller.states),'seconds':round(time.monotonic()-started,2)}
 except Exception as exc:
  result={'result':type(exc).__name__,'states':len(controller.states),'seconds':round(time.monotonic()-started,2)}
 print(json.dumps(result),flush=True)
 browser.close()
server.shutdown()
"""
settings = Settings()
container = docker.from_env().containers.run(
    settings.browser_worker_image,
    ["python", "-c", CODE],
    network_mode="none",
    read_only=True,
    tmpfs={"/tmp": "rw,nosuid,size=512m"},
    mem_limit="1024m",
    shm_size="256m",
    pids_limit=512,
    cap_drop=["ALL"],
    security_opt=["no-new-privileges:true", "seccomp=" + settings.browser_seccomp_path.read_text()],
    init=True,
    detach=True,
    environment={"HOME": "/tmp/browser-home"},
)
try:
    status = container.wait(timeout=60)
    output = container.logs().decode("utf8", "replace")
    print(output)
    results = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    assert status["StatusCode"] == 0 and results and results[-1]["result"] == "captured"
finally:
    container.remove(force=True)
