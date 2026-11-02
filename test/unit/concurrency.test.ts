import { describe, expect, it } from 'vitest';
import { mapLimit } from '../../src/core/concurrency';

const tick = () => new Promise((r) => setTimeout(r, 1));

describe('mapLimit', () => {
  it('keeps order and never exceeds the limit', async () => {
    let active = 0;
    let peak = 0;
    const out = await mapLimit([1, 2, 3, 4, 5, 6, 7], 3, async (n) => {
      active++;
      peak = Math.max(peak, active);
      await tick();
      active--;
      return n * 2;
    });
    expect(out).toEqual([2, 4, 6, 8, 10, 12, 14]);
    expect(peak).toBe(3);
  });

  it('handles empty input and limits below one', async () => {
    expect(await mapLimit([], 4, async () => 1)).toEqual([]);
    expect(await mapLimit([1, 2], 0, async (n) => n)).toEqual([1, 2]);
  });

  it('stops when aborted', async () => {
    const ctrl = new AbortController();
    const seen: number[] = [];
    const run = mapLimit(
      [1, 2, 3, 4],
      1,
      async (n) => {
        seen.push(n);
        if (n === 2) ctrl.abort();
        await tick();
        return n;
      },
      ctrl.signal,
    );
    await expect(run).rejects.toThrow();
    expect(seen).toEqual([1, 2]);
  });
});
