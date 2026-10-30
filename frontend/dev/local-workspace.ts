import { loadEnv, type Plugin } from 'vite';
import { resolve } from 'node:path';

/** Explicit local development convenience. Never part of the production bundle. */
export function localWorkspace(): Plugin {
  return {
    name: 'scopelens-local-workspace',
    apply: 'serve',
    configureServer(server) {
      const env = loadEnv('development', resolve(server.config.root, '..'), 'SCOPELENS_');
      const enabled = process.env.SCOPELENS_LOCAL_WORKSPACE === '1';
      server.middlewares.use('/__local/session', async (req, res) => {
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Content-Type', 'application/json');
        const send = (status: number, detail: string) => { res.statusCode = status; res.end(JSON.stringify({ detail })); };
        if (!enabled) return send(404, 'Local workspace session is not enabled.');
        const port = server.config.server.port ?? 5173;
        const hosts = [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`];
        if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress ?? '') || !hosts.includes(req.headers.host ?? '') || req.headers.origin !== `http://${req.headers.host}` || req.headers['x-scopelens-local'] !== '1') return send(403, 'Local same-origin requests only.');
        if (req.method !== 'POST') return send(405, 'POST required.');
        const username = env.SCOPELENS_OPERATOR_USERNAME;
        const password = env.SCOPELENS_OPERATOR_PASSWORD;
        if (!username || !password) return send(503, 'Configure the local operator credentials in .env.');
        try {
          const result = await fetch(`http://127.0.0.1:${process.env.SCOPELENS_API_PORT ?? '8090'}/api/auth/login`, {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ username, password }), signal: AbortSignal.timeout(10000),
          });
          if (!result.ok) return send(503, 'The backend could not establish the local operator session.');
          const cookies = result.headers.getSetCookie();
          if (!cookies.length) return send(503, 'The backend did not return a session.');
          res.setHeader('Set-Cookie', cookies);
          res.statusCode = 204; res.end();
        } catch { send(503, 'The backend is unavailable. Start the backend and retry.'); }
      });
    },
  };
}
