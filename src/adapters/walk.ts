import { lstat, readdir } from 'node:fs/promises';
import * as path from 'node:path';
import type { ScanLimits } from '../core/types';

export interface WalkOptions {
  limits: ScanLimits;
  /** Directory basenames never descended into. */
  skipDirs: ReadonlySet<string>;
  /** Whether a file (absolute path) is worth scanning. */
  include: (file: string) => boolean;
}

/**
 * Sorted, depth-first list of files under `root`. Symlinks are not followed, so a package
 * cannot point the scanner outside itself. Oversized files and files beyond the per-package
 * cap are dropped.
 */
export async function walkFiles(root: string, opts: WalkOptions): Promise<string[]> {
  const out: string[] = [];
  const visit = async (dir: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (out.length >= opts.limits.maxFilesPerPackage) return;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!opts.skipDirs.has(entry.name)) await visit(full);
      } else if (entry.isFile() && opts.include(full)) {
        const { size } = await lstat(full);
        if (size <= opts.limits.maxFileSizeBytes) out.push(full);
      }
    }
  };
  await visit(root);
  return out;
}
