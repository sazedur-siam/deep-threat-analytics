import { createHash } from 'node:crypto';
import type { PackageRef } from './types';

/** Deterministic id so the same issue keeps its id across scans (used by cache and ignores). */
export function makeFindingId(
  ruleId: string,
  pkg: PackageRef,
  file?: string,
  line?: number,
): string {
  const key = [ruleId, pkg.ecosystem, pkg.name, pkg.version, file ?? '', line ?? ''].join('\0');
  return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

export function packageKey(pkg: PackageRef): string {
  return `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
}

/** Collapse whitespace and cap length for display. */
export function trimEvidence(text: string, max = 200): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}
