import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { CACHE_FORMAT, ScanCache } from '../../src/core/cache';
import type { Finding } from '../../src/core/types';

const pkg = { ecosystem: 'npm', name: 'a', version: '1.0.0' } as const;
const finding = { id: 'f1', ruleId: 'exec/x' } as Finding;

async function tempFile(): Promise<string> {
  return path.join(await mkdtemp(path.join(tmpdir(), 'depthreat-cache-')), 'sub', 'cache.json');
}

describe('ScanCache', () => {
  it('keys on package, rules hash and install path', () => {
    const k = ScanCache.key(pkg, 'h1', '/p');
    expect(k).toBe('npm:a@1.0.0|h1|/p');
    expect(k).not.toBe(ScanCache.key(pkg, 'h2', '/p'));
    expect(ScanCache.key(pkg, 'h1')).toBe('npm:a@1.0.0|h1|');
  });

  it('round-trips through disk', async () => {
    const file = await tempFile();
    const a = new ScanCache(file);
    a.set('k', [finding]);
    await a.save();
    const b = new ScanCache(file);
    await b.load();
    expect(b.get('k')).toEqual([finding]);
    expect(b.size).toBe(1);
  });

  it('skips writing when nothing changed', async () => {
    const file = await tempFile();
    const cache = new ScanCache(file);
    await cache.save();
    await expect(readFile(file)).rejects.toThrow();
  });

  it('expires entries after the ttl', () => {
    let now = 1000;
    const cache = new ScanCache('/unused', { ttlMs: 50, now: () => now });
    cache.set('k', [finding]);
    now = 1040;
    expect(cache.get('k')).toBeDefined();
    now = 1100;
    expect(cache.get('k')).toBeUndefined();
    expect(cache.size).toBe(0);
  });

  it('ignores missing, corrupt or old-format files', async () => {
    const file = await tempFile();
    const cache = new ScanCache(file);
    await cache.load();
    expect(cache.size).toBe(0);

    const dir = path.dirname(path.dirname(file));
    const corrupt = path.join(dir, 'corrupt.json');
    await writeFile(corrupt, '{not json');
    const c2 = new ScanCache(corrupt);
    await c2.load();
    expect(c2.size).toBe(0);

    const old = path.join(dir, 'old.json');
    await writeFile(old, JSON.stringify({ format: CACHE_FORMAT + 1, entries: { k: {} } }));
    const c3 = new ScanCache(old);
    await c3.load();
    expect(c3.size).toBe(0);
  });

  it('clears all entries', async () => {
    const file = await tempFile();
    const cache = new ScanCache(file);
    cache.set('k', [finding]);
    await cache.save();
    cache.clear();
    await cache.save();
    const reloaded = new ScanCache(file);
    await reloaded.load();
    expect(reloaded.size).toBe(0);
  });
});
