import type { EcosystemAdapter } from '../adapters/adapter';
import type { DepThreatSettings } from '../config/settings';
import type { OnlineCheck } from '../core/engine';
import type { EcosystemId, Finding } from '../core/types';
import { queryOsv } from './osv';
import { checkTyposquat, fetchRegistryReputation, loadTopPackages } from './reputation';

/**
 * Package-level checks for the engine. The offline typosquat check always runs; OSV and
 * registry lookups are included only when their settings are enabled.
 */
export function createPackageChecks(
  settings: DepThreatSettings,
  adapters: readonly EcosystemAdapter[],
  dataDir: string,
  fetchImpl?: typeof fetch,
): OnlineCheck[] {
  const topCache = new Map<EcosystemId, Promise<string[]>>();
  const top = (e: EcosystemId) => {
    if (!topCache.has(e)) topCache.set(e, loadTopPackages(e, dataDir));
    return topCache.get(e)!;
  };
  const checks: OnlineCheck[] = [
    async (deps) => {
      const findings: Finding[] = [];
      for (const dep of deps) {
        const f = checkTyposquat(dep, await top(dep.ecosystem));
        if (f) findings.push(f);
      }
      return { findings, errors: [] };
    },
  ];
  if (settings.online.osv) {
    const osvName = (e: EcosystemId) => adapters.find((a) => a.id === e)?.osvEcosystem ?? e;
    checks.push((deps, signal) =>
      queryOsv(deps, osvName, {
        enabled: true,
        ...(signal ? { signal } : {}),
        ...(fetchImpl ? { fetchImpl } : {}),
      }),
    );
  }
  if (settings.online.registryMetadata) {
    checks.push((deps, signal) =>
      fetchRegistryReputation(deps, {
        enabled: true,
        ...(signal ? { signal } : {}),
        ...(fetchImpl ? { fetchImpl } : {}),
      }),
    );
  }
  return checks;
}
