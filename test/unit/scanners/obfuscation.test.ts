import { describe, expect, it } from 'vitest';
import type { ResolvedDep } from '../../../src/core/types';
import { detectObfuscation, shannonEntropy } from '../../../src/scanners/obfuscation';

const dep: ResolvedDep = {
  ecosystem: 'npm',
  name: 'pkg',
  version: '1.0.0',
  installPath: '/pkg',
  direct: true,
  isDev: false,
};

/** Deterministic pseudo-random string over an alphabet (high entropy, not real data). */
function noise(alphabet: string, length: number, seed = 7): string {
  let x = seed;
  let out = '';
  for (let i = 0; i < length; i++) {
    x = (x * 1103515245 + 12345) % 2147483648;
    out += alphabet[(x >>> 16) % alphabet.length];
  }
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const ids = (text: string, language: 'javascript' | 'python' = 'javascript') =>
  detectObfuscation('/pkg/x', 'x', text, dep, language).map((f) => f.ruleId);

describe('shannonEntropy', () => {
  it('is zero for empty or uniform strings and grows with variety', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('abcd')).toBe(2);
    expect(shannonEntropy(noise(B64, 2000))).toBeGreaterThan(5.5);
  });
});

describe('detectObfuscation', () => {
  const payload = noise(B64, 400);

  it('flags a high-entropy payload next to an execution sink', () => {
    const js = `const p = "${payload}"; eval(Buffer.from(p, "base64").toString());`;
    const [f] = detectObfuscation('/pkg/x.js', 'x.js', js, dep, 'javascript');
    expect(f).toMatchObject({
      ruleId: 'obfuscation/encoded-payload-exec',
      category: 'obfuscation',
      severity: 'high',
      source: 'code',
      location: { file: '/pkg/x.js' },
    });
    expect(f?.message).toContain('400-character base64 payload');
    expect(ids(`p = "${payload}"\nexec(base64.b64decode(p))`, 'python')).toContain(
      'obfuscation/encoded-payload-exec',
    );
  });

  it('flags hex payloads', () => {
    const hex = noise('0123456789abcdef', 400);
    expect(ids(`const h = '${hex}'; new Function(h)();`)).toContain(
      'obfuscation/encoded-payload-exec',
    );
  });

  it('ignores payloads without an execution sink and low-entropy blobs', () => {
    expect(ids(`const font = "${payload}";`)).toEqual([]);
    expect(ids(`const pad = "${'A'.repeat(400)}"; eval(x);`)).toEqual([]);
  });

  it('does not flag ordinary minified code', () => {
    const minified = Array.from(
      { length: 300 },
      (_, i) => `function a${i}(b,c){return b+c*${i}}`,
    ).join(';');
    expect(ids(minified)).toEqual([]);
  });

  it('flags javascript-obfuscator output, more severely with a sink', () => {
    const obf = Array.from({ length: 25 }, (_, i) => `var _0x${(0xa1b2 + i).toString(16)}=1;`).join(
      '',
    );
    const plain = detectObfuscation('/pkg/x', 'x', obf, dep, 'javascript');
    expect(plain[0]).toMatchObject({ ruleId: 'obfuscation/js-obfuscator', severity: 'medium' });
    const withSink = detectObfuscation('/pkg/x', 'x', `${obf}eval(_0xa1b2);`, dep, 'javascript');
    expect(withSink[0]?.severity).toBe('high');
    expect(ids('var _0xa1b2 = 1;')).toEqual([]);
  });

  it('flags strings assembled from character codes', () => {
    const code = Array.from({ length: 5 }, () => 'String.fromCharCode(104,105)').join('+');
    expect(ids(code)).toContain('obfuscation/char-code-strings');
    expect(ids('String.fromCharCode(65)')).toEqual([]);
  });

  it('flags long hex-escaped strings only next to dynamic execution', () => {
    const escaped = '\\x68'.repeat(50);
    expect(ids(`eval("${escaped}")`)).toContain('obfuscation/hex-escaped-strings');
    expect(ids(`const s = "${escaped}";`)).toEqual([]);
  });

  it('only checks escapes for languages without a sink definition', () => {
    expect(ids(`echo "${payload}"`, 'shell' as never)).toEqual([]);
  });
});
