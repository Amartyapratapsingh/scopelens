// Run with: ego-browser nodejs < frontend/tests/host-inventory.browser.mjs
// All API requests are mocked before app boot. This test never starts a scan.
const fs = await import('node:fs/promises');
const assert = (await import('node:assert/strict')).default;
const report = JSON.parse(await fs.readFile('/Users/adityapratapsingh/dev/scopelense/runs/fallback-validation/repeat-export.json', 'utf8'));
const priorities = JSON.parse(await fs.readFile('/Users/adityapratapsingh/dev/scopelense/runs/college-subdomains/host-priorities.json', 'utf8'));
const task = await taskSpace(33), page = task.page('p1');
const fixture = {
  scans: [{id:'inventory-fixture', target_origin:'https://example.test', status:'completed_partial', profile:'external-dast', status_reason:'Fixture scan with incomplete discovery', created_at:'2026-09-29T06:00:00Z', started_at:'2026-09-29T06:00:00Z', finished_at:'2026-09-29T06:05:00Z', findings_count:0, progress_percent:100}],
  hosts: report.host_inventory,
  priorities,
  summary: {overall_score:null, overall_state:'insufficient_coverage', overall_label:'Insufficient coverage', overall_reason:'Fixture only', coverage_percent:4.5, findings_count:0, discovery:{pages_fetched:110, stopped_by:'crawl time budget reached (120s)'}},
};
const source = `(() => {
 const fixture=${JSON.stringify(fixture)}; window.__inventoryFixture=fixture; window.__inventoryRequests=[];
 const original=window.fetch.bind(window);
 window.fetch=async(input,init={})=>{
  const path=String(input);if(!path.startsWith('/api/')&&!path.startsWith('/__local/'))return original(input,init);
  window.__inventoryRequests.push({path,method:init.method||'GET'});
  if(path.endsWith('/hosts')&&fixture.failHosts)return new Response('{}',{status:503});
  const value=path==='/api/scans'?fixture.scans:path.endsWith('/summary')?fixture.summary:path.endsWith('/hosts')?fixture.hosts:path.endsWith('/host-priorities')?fixture.priorities:path.endsWith('/me')?{username:'fixture'}:[];
  return new Response(JSON.stringify(value),{status:200,headers:{'content-type':'application/json'}});
 };
 window.EventSource=class {addEventListener(){} close(){}};
})();`;
const {identifier}=await page.cdp('Page.addScriptToEvaluateOnNewDocument',{source});
try {
 await page.goto('http://127.0.0.1:5173/dashboard?scan=inventory-fixture');
 await page.waitForFunction(()=>document.querySelector('.dash-host-list'));
 const initial=await page.evaluate(()=>({text:document.querySelector('.dash-hosts').textContent,rows:document.querySelectorAll('.dash-host-list>li').length,posts:window.__inventoryRequests.filter(r=>r.method!=='GET')}));
 assert.equal(initial.rows,8); assert.match(initial.text,/portal\.alliance\.edu\.in/);assert.match(initial.text,/student\.alliance\.edu\.in/);
 assert.match(initial.text,/linked from \//);assert.match(initial.text,/Discovered · not assessed/);assert.match(initial.text,/crawl time budget reached \(120s\)/);assert.deepEqual(initial.posts,[]);
 await page.waitForFunction(()=>document.querySelector('.dash-host-plan summary'));
 await page.evaluate(()=>document.querySelector('.dash-host-plan summary').click());
 assert.match(await page.evaluate(()=>document.querySelector('.dash-host-plan').textContent),/Test accounts needed/);
 assert.equal(await page.evaluate(()=>document.querySelector('.dash-host-name strong').textContent),'portal.alliance.edu.in');
 await page.evaluate(()=>document.querySelector('.dash-hosts-footer button').click());
 await page.waitForFunction(()=>document.querySelectorAll('.dash-host-list>li').length===42);
 // Native value setter exercises React's real input handler.
 await page.evaluate(()=>{const input=document.querySelector('[aria-label="Search discovered websites"]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'portal.');input.dispatchEvent(new Event('input',{bubbles:true}));});
 await page.waitForFunction(()=>document.querySelectorAll('.dash-host-list>li').length===1);
 assert.match(await page.evaluate(()=>document.querySelector('.dash-host-list').textContent),/portal\.alliance\.edu\.in/);
 await page.cdp('Emulation.setDeviceMetricsOverride',{width:312,height:720,deviceScaleFactor:1,mobile:false});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth),false);
 await page.evaluate(()=>{window.__inventoryFixture.failHosts=true;});
 await page.waitForFunction(()=>document.querySelector('.dash-hosts [role="status"]'),undefined,{timeout:15000});
 assert.match(await page.evaluate(()=>document.querySelector('.dash-hosts').textContent),/Showing the last loaded inventory/);
 assert.equal(await page.evaluate(()=>window.__inventoryRequests.filter(r=>r.method!=='GET').length),0);
 console.log('PASS: saved report portal/student, provenance, 42 hosts, search, stop reason, mobile overflow, stale-data error, evidence priority, blocked credentials, zero mutations.');
} finally {
 await page.cdp('Page.removeScriptToEvaluateOnNewDocument',{identifier});
 await page.cdp('Emulation.clearDeviceMetricsOverride');
 await page.goto('http://127.0.0.1:5181/');
}
