import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import { packageKey } from './findings';
import type { Finding, PackageRef } from './types';

/** Bump when scanner behavior changes so stale results are not reused. */
export const CACHE_FORMAT = 1;

interface Entry {
  findings: Finding[];
  storedAt: number;
}

interface CacheFile {
  format: number;
  entries: Record<string, Entry>;
}

export interface CacheOptions {
  /** Entries older than this are ignored; undefined = never expire. */
  ttlMs?: number;
  now?: () => number;
}

/**
 * Per-package scan results persisted as one JSON file. Keys include the rule-set hash and
 * install path, so editing rules or reinstalling a package invalidates the entry.
 */
export class ScanCache {
  private entries = new Map<string, Entry>();
  private dirty = false;
  private readonly now: () => number;

  constructor(
    private readonly file: string,
    private readonly options: CacheOptions = {},
  ) {
    this.now = options.now ?? Date.now;
  }

  static key(pkg: PackageRef, rulesHash: string, installPath = ''): string {
    return `${packageKey(pkg)}|${rulesHash}|${installPath}`;
  }

  get size(): number {
    return this.entries.size;
  }

  async load(): Promise<void> {
    this.entries.clear();
    let parsed: CacheFile;
    try {
      parsed = JSON.parse(await readFile(this.file, 'utf8')) as CacheFile;
    } catch {
      return;
    }
    if (parsed.format !== CACHE_FORMAT || typeof parsed.entries !== 'object') return;
    for (const [key, entry] of Object.entries(parsed.entries)) this.entries.set(key, entry);
  }

  get(key: string): Finding[] | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    const { ttlMs } = this.options;
    if (ttlMs !== undefined && this.now() - entry.storedAt > ttlMs) {
      this.entries.delete(key);
      this.dirty = true;
      return undefined;
    }
    return entry.findings;
  }

  set(key: string, findings: Finding[]): void {
    this.entries.set(key, { findings, storedAt: this.now() });
    this.dirty = true;
  }

  clear(): void {
    this.entries.clear();
    this.dirty = true;
  }

  /** Atomic write (temp file + rename); no-op when nothing changed. */
  async save(): Promise<void> {
    if (!this.dirty) return;
    const data: CacheFile = { format: CACHE_FORMAT, entries: Object.fromEntries(this.entries) };
    await mkdir(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(data));
    await rename(tmp, this.file);
    this.dirty = false;
  }
}
