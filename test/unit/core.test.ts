import { describe, expect, it } from 'vitest';
import { makeFindingId, packageKey, trimEvidence } from '../../src/core/findings';
import { maxSeverity, severityRank } from '../../src/core/types';

const pkg = { ecosystem: 'npm', name: 'left-pad', version: '1.3.0' } as const;

describe('severity helpers', () => {
  it('ranks severities in order', () => {
    expect(severityRank('info')).toBeLessThan(severityRank('critical'));
  });

  it('picks the highest severity', () => {
    expect(maxSeverity(['low', 'critical', 'medium'])).toBe('critical');
    expect(maxSeverity([])).toBeUndefined();
  });
});

describe('finding helpers', () => {
  it('makes stable, location-sensitive ids', () => {
    const a = makeFindingId('exec/x', pkg, '/a.js', 3);
    expect(a).toBe(makeFindingId('exec/x', pkg, '/a.js', 3));
    expect(a).not.toBe(makeFindingId('exec/x', pkg, '/a.js', 4));
    expect(makeFindingId('exec/x', pkg)).toHaveLength(16);
  });

  it('formats package keys', () => {
    expect(packageKey(pkg)).toBe('npm:left-pad@1.3.0');
  });

  it('flattens and truncates evidence', () => {
    expect(trimEvidence('  a\n\t b  ')).toBe('a b');
    const long = trimEvidence('x'.repeat(500), 10);
    expect(long).toHaveLength(10);
    expect(long.endsWith('…')).toBe(true);
  });
});
