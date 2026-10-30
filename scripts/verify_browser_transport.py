"""Bounded browser transport reproduction inside a network-disabled VM worker.

Run through the trusted supervisor, like verify_browser_readiness.py. This test never
contacts a customer or uses a real egress token. A loopback fixture and the real Bridge,
Controller route handlers and Chromium sandbox reproduce an unfinished parser script.
Optionally provide --worker-source to verify source before deploying a worker image.
"""

import argparse
import base64
import gzip
import json
from pathlib import Path

import docker

from scopelens.config import Settings

CODE = r"""
import contextlib,io,json,os,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright
from scopelens.browser import worker
from scopelens.browser.bridge import Bridge
from scopelens.browser.policy import BrowserAction
from scopelens.checks.crawl import CrawlConfig
SOURCE_OVERRIDE
class Handler(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def do_GET(self):
  path=urlsplit(self.path).path
  if path=='/blocked.js':
   self.send_response(200);self.send_header('Content-Type','application/javascript')
   self.send_header('Content-Length','10000');self.end_headers()
   # A response-start event is not a completed asset. Keep the transport alive
   # without finishing the script or letting Chromium advance the parser.
   with contextlib.suppress(BrokenPipeError,ConnectionResetError):
    for _ in range(50):self.wfile.write(b' ');self.wfile.flush();time.sleep(1)
   return
  body=b'window.fixtureLoaded=true' if path=='/fast.js' else (
   b'<html><head><script src="'+(b'/blocked.js' if path=='/pending' else b'/fast.js')+
   b'"></script></head><body><button>View details</button></body></html>')
  self.send_response(200)
  self.send_header('Content-Type','application/javascript' if path=='/fast.js' else 'text/html')
  self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
os.environ['SCOPELENS_EGRESS_TOKEN']='synthetic-transport-fixture'
with Bridge('http://127.0.0.1:'+str(server.server_port),'synthetic-transport-fixture') as proxy:
 with sync_playwright() as p:
  browser=p.chromium.launch(headless=True,chromium_sandbox=True,proxy={'server':proxy})
  for variant in ('normal','pending'):
   context=browser.new_context(service_workers='block')
   c=worker.Controller(CrawlConfig(origin='http://fixture.invalid',scheme='http',host='fixture.invalid',port=80,
      max_pages=10,max_depth=1,timeout=10,max_body_bytes=1048576,user_agent='fixture'),proxy,'fixture')
   c.context_id='local-transport-fixture';commands=[]
   c.command=lambda operation,**fields:commands.append({'operation':operation,**fields})
   context.route('**/*',c.route)
   page=context.new_page();page.set_default_timeout(5000);page.set_default_navigation_timeout(15000)
   page.on('request',c.request_started);page.on('requestfinished',c.request_finished)
   page.on('requestfailed',c.request_failed)
   url='http://fixture.invalid/'+variant;start=time.monotonic()
   with contextlib.redirect_stdout(io.StringIO()):
    try:
     c.act(page,BrowserAction(kind='navigate',url=url),lambda:page.goto(url,wait_until='commit'))
     result='captured'
    except Exception as exc:result=type(exc).__name__
   diagnostics=[g for g in c.gaps if g['reason']=='document_ready_timeout']
   output={'variant':variant,'result':result,'states':len(c.states),'responses':len(c.responses),
           'seconds':round(time.monotonic()-start,2),'readiness_diagnostics':diagnostics}
   print(json.dumps(output),flush=True)
   if variant=='normal':
    assert result=='captured' and len(c.states)==1 and 'View details' in c.states[0]['text']
    assert commands[-1]['result']=='succeeded'
   else:
    assert result=='TimeoutError' and not c.states and diagnostics
    assert diagnostics[0]['pending_request_count']==1
    assert diagnostics[0]['pending_requests'][0]['resource_type']=='script'
    assert diagnostics[0]['pending_requests'][0]['pending_seconds']>=29
    assert not any(r['url'].endswith('/blocked.js') for r in c.responses)
    assert commands[-1]['result']=='failed' and not commands[-1]['after_hash']
   context.close();c.http.close()
  browser.close()
server.shutdown();server.server_close()
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-source", type=Path)
    args = parser.parse_args()
    override = ""
    if args.worker_source:
        source = args.worker_source.read_text()
        override = f"exec({source!r}, worker.__dict__)"
    code = CODE.replace("SOURCE_OVERRIDE", override)
    packed = base64.b64encode(gzip.compress(code.encode())).decode()
    chunks = [packed[i : i + 60000] for i in range(0, len(packed), 60000)]
    settings = Settings()
    container = docker.from_env().containers.run(
        settings.browser_worker_image,
        [
            "python",
            "-c",
            "import sys,gzip,base64;exec(gzip.decompress(base64.b64decode(''.join(sys.argv[1:]))))",
            *chunks,
        ],
        network_mode="none",
        read_only=True,
        tmpfs={"/tmp": "rw,nosuid,size=512m"},
        mem_limit="1024m",
        shm_size="256m",
        pids_limit=512,
        cap_drop=["ALL"],
        security_opt=[
            "no-new-privileges:true",
            "seccomp=" + settings.browser_seccomp_path.read_text(),
        ],
        init=True,
        detach=True,
        environment={"HOME": "/tmp/browser-home"},
    )
    try:
        status = container.wait(timeout=55)
        output = container.logs().decode("utf8", "replace")
        print(output)
        results = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
        assert status["StatusCode"] == 0 and len(results) == 2
    finally:
        container.remove(force=True)


if __name__ == "__main__":
    main()
