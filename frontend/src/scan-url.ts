/** Keep the entered origin and path; never silently widen a path-scoped scan. */
export function websiteScope(value: string) {
  const trimmed = value.trim();
  let url: URL;
  try { url = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`); }
  catch { throw new Error('Enter a valid website URL, such as https://your-website.com.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash) {
    throw new Error('Use an HTTP or HTTPS website URL without credentials, query parameters, or a fragment.');
  }
  return {
    authority_domain: 'production', host: url.hostname, scheme: url.protocol.slice(0, -1),
    port: Number(url.port || (url.protocol === 'https:' ? 443 : 80)),
    allowed_path_prefixes: [url.pathname || '/'], excluded_paths: [], allowed_methods: ['GET', 'HEAD'],
    allowed_check_profile: 'external-dast',
    authorization_expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    owner_note: 'Operator requested website assessment from the local dashboard.',
  };
}
