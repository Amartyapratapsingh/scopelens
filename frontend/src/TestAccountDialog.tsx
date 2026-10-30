import { useEffect, useRef, useState } from 'react';
import { CheckCircle, DownloadSimple, LockKey, X } from '@phosphor-icons/react';
import { api, type ScopeView } from './api';
import './test-account.css';

type Receipt = {
  version: string; origin: string; scope_version_id: string; role: string;
  expires_at: string; credential_references: {username: string; password: string};
  login_verified: false; state: string;
};

/** Credentials stay in uncontrolled inputs, never browser storage or assessment prose. */
export function TestAccountDialog({open, scopes, onClose}: {
  open: boolean; scopes: ScopeView[]; onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const form = useRef<HTMLFormElement>(null);
  const inFlight = useRef(false);
  const partial = useRef<{scope: ScopeView; role: string; expiry: string; usernameRef: string} | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const choices = scopes.filter(s => !s.expired && ['authenticated-api-v1', 'staging-stateful-v1'].includes(s.allowed_check_profile));
  useEffect(() => {
    if (open) dialog.current?.showModal();
    else { dialog.current?.close(); form.current?.reset(); }
  }, [open]);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (inFlight.current || receipt || !form.current) return;
    const fields = new FormData(form.current);
    const scope = partial.current?.scope ?? choices.find(s => s.id === fields.get('scope'));
    if (!scope) { setError('Choose an unexpired scope for authenticated testing.'); return; }
    const password = String(fields.get('password') ?? '');
    const username = String(fields.get('username') ?? '').trim();
    if (!password || (!partial.current && !username)) return;
    const role = String(fields.get('role') ?? 'student');
    const expiry = partial.current?.expiry ?? new Date(Math.min(Date.now() + 4 * 3600_000, Date.parse(scope.authorization_expires_at))).toISOString();
    inFlight.current = true; setBusy(true); setError('');
    try {
      if (!partial.current) {
        const saved = await api.saveCredential({scope_version_id: scope.id, value: username, expires_at: expiry});
        partial.current = {scope, role, expiry, usernameRef: saved.reference};
      }
      const pending = partial.current;
      const saved = await api.saveCredential({scope_version_id: pending.scope.id, value: password, expires_at: pending.expiry});
      setReceipt({version: 'test-account-setup-v1', origin: pending.scope.origin, scope_version_id: pending.scope.id,
        role: pending.role, expires_at: pending.expiry,
        credential_references: {username: pending.usernameRef, password: saved.reference},
        login_verified: false, state: 'login_configuration_pending'});
      partial.current = null;
      form.current.reset();
    } catch {
      setError(partial.current
        ? 'The username was saved, but password storage was not confirmed. Re-enter the password to finish. No login or scan has started.'
        : 'Credential storage was not confirmed. Check the backend connection and scope expiry. No login or scan has started.');
    } finally {
      const input = form.current?.elements.namedItem('password');
      if (input instanceof HTMLInputElement) input.value = '';
      fields.delete('password'); fields.delete('username');
      inFlight.current = false; setBusy(false);
    }
  }
  function download() {
    if (!receipt) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(receipt, null, 2)], {type: 'application/json'}));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'test-account-setup.json'; anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <dialog ref={dialog} className="dash-dialog test-account-dialog" aria-labelledby="test-account-title"
    onCancel={e => { if (inFlight.current) e.preventDefault(); }} onClose={onClose}>
    <div className="dash-panel-heading"><h2 id="test-account-title"><LockKey size={23} /> Test account</h2>
      <button type="button" className="dash-icon-button" disabled={busy} aria-label="Close test account" onClick={onClose}><X size={20} /></button></div>
    {receipt ? <div className="test-account-saved" role="status"><CheckCircle size={32} /><h3>Credentials encrypted locally</h3>
      <p>{receipt.origin} · {receipt.role} account</p><p>Expires {new Date(receipt.expires_at).toLocaleString()}.</p>
      <p>Download the setup references to connect this account to a reviewed login flow. The file contains no password. Login has not been verified and no scan has started.</p>
      <button className="ops-btn is-primary" onClick={download}><DownloadSimple size={18} /> Download setup references</button>
      <button className="ops-btn" onClick={() => { setReceipt(null); setError(''); }}>Add another account</button>
    </div> : <form ref={form} onSubmit={save}>
      <p>Save a dedicated testing account for a registered website. Credentials are encrypted on the backend and are never sent to the AI.</p>
      {!choices.length ? <p className="dash-banner">An unexpired authenticated assessment scope is needed first. Register the website with the authenticated-api-v1 profile.</p> : <>
        {partial.current && <p role="status">Username already encrypted for {partial.current.scope.origin}. Enter the password to complete storage.</p>}
        <fieldset disabled={busy || !!partial.current}><label htmlFor="test-account-scope">Website scope</label>
          <select id="test-account-scope" name="scope" required defaultValue={partial.current?.scope.id ?? choices[0]?.id}>{choices.map(s => <option key={s.id} value={s.id}>{s.origin} · expires {new Date(s.authorization_expires_at).toLocaleDateString()}</option>)}</select>
          <label htmlFor="test-account-role">Account role</label><select id="test-account-role" name="role" defaultValue="student"><option value="student">Student test account</option><option value="staff">Staff test account</option><option value="other">Other test account</option></select>
          <label htmlFor="test-account-username">Username or email</label><input id="test-account-username" name="username" autoComplete="off" spellCheck={false} required />
        </fieldset>
        <label htmlFor="test-account-password">Password</label><input id="test-account-password" name="password" type="password" autoComplete="off" required disabled={busy} />
        <p className="test-account-note">Saving only stores credentials. The account still needs a verified login flow before authenticated checks can run. Access expires within four hours or when the scope expires.</p>
        {error && <p className="dash-error" role="alert">{error}</p>}
        <button className="ops-btn is-primary" disabled={busy}>{busy ? 'Encrypting…' : 'Save encrypted credentials'}<LockKey size={18} /></button>
      </>}
    </form>}
  </dialog>;
}
