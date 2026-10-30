import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { localWorkspace } from '../dev/local-workspace.ts';
import { websiteScope } from '../src/scan-url.ts';

test('URL scope preserves the supplied path and port, and rejects credential/query URLs', () => {
  const scope = websiteScope('https://example.com:8443/project/');
  assert.equal(scope.port, 8443);
  assert.deepEqual(scope.allowed_path_prefixes, ['/project/']);
  assert.equal(scope.authority_domain, 'production');
  assert.equal(websiteScope('example.com').scheme, 'https');
  for (const url of ['ftp://example.com', 'https://user:pass@example.com', 'https://example.com/?token=x', 'https://example.com/#route']) assert.throws(() => websiteScope(url));
});

test('local bootstrap is opt-in, loopback-only, same-origin and never returns credentials', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'scopelens-session-test-'));
  const previous = process.env.SCOPELENS_LOCAL_WORKSPACE;
  const originalFetch = globalThis.fetch;
  writeFileSync(join(directory, '.env'), 'SCOPELENS_OPERATOR_USERNAME=fixture\nSCOPELENS_OPERATOR_PASSWORD=fixture-password\n');
  let loginCalls = 0;
  globalThis.fetch = async () => { loginCalls++; return new Response('{}', {status:200,headers:{'set-cookie':'session=fixture; HttpOnly; SameSite=Lax; Path=/'}}); };
  function middleware(enabled) {
    if (enabled) process.env.SCOPELENS_LOCAL_WORKSPACE = '1'; else delete process.env.SCOPELENS_LOCAL_WORKSPACE;
    let handler;
    localWorkspace().configureServer({config:{root:join(directory,'frontend'),server:{port:5173}},middlewares:{use:(_path, fn)=>{handler=fn;}}});
    return handler;
  }
  async function request(handler, overrides={}) {
    const req = {method:'POST',socket:{remoteAddress:'127.0.0.1'},headers:{host:'127.0.0.1:5173',origin:'http://127.0.0.1:5173','x-scopelens-local':'1'},...overrides};
    const res = {statusCode:200,headers:{},setHeader(k,v){this.headers[k]=v;},end(body){this.body=body;}};
    await handler(req,res); return res;
  }
  try {
    assert.equal((await request(middleware(false))).statusCode,404);
    const handler=middleware(true);
    assert.equal((await request(handler,{socket:{remoteAddress:'192.0.2.1'}})).statusCode,403);
    assert.equal((await request(handler,{headers:{host:'attacker.test:5173',origin:'http://attacker.test:5173','x-scopelens-local':'1'}})).statusCode,403);
    assert.equal((await request(handler,{headers:{host:'127.0.0.1:5173',origin:'https://attacker.test','x-scopelens-local':'1'}})).statusCode,403);
    assert.equal((await request(handler,{headers:{host:'127.0.0.1:5173',origin:'http://127.0.0.1:5173'}})).statusCode,403);
    assert.equal((await request(handler,{method:'GET'})).statusCode,405);
    assert.equal(loginCalls,0);
    const success=await request(handler);
    assert.equal(success.statusCode,204);
    assert.equal(success.body,undefined);
    assert.match(success.headers['Set-Cookie'][0],/HttpOnly/);
    assert.equal(loginCalls,1);
    globalThis.fetch=async()=>new Response('{}',{status:401});
    const failure=await request(handler);
    assert.equal(failure.statusCode,503);
    assert.equal(failure.headers['Set-Cookie'],undefined);
    assert.ok(!failure.body.includes('fixture-password'));
  } finally {
    globalThis.fetch=originalFetch;
    if (previous===undefined) delete process.env.SCOPELENS_LOCAL_WORKSPACE; else process.env.SCOPELENS_LOCAL_WORKSPACE=previous;
    rmSync(directory,{recursive:true});
  }
});
