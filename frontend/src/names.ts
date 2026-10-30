import type { ScanView, ScopeView } from './api';

/** Human name for a scan target: lab service name for lab scopes, hostname otherwise. */
export function targetName(origin: string, scope?: Pick<ScopeView, 'lab_binding'> | null) {
  if (scope?.lab_binding?.service) return scope.lab_binding.service;
  try { return new URL(origin).hostname; } catch { return origin; }
}
export const scanName = (scan: ScanView, scopes: ScopeView[]) =>
  targetName(scan.target_origin, scopes.find(s => s.id === scan.scope_version_id));
