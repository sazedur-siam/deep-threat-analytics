import { findNodeAtLocation, parseTree } from 'jsonc-parser';
import { existsSync } from 'node:fs';
import { readFile as fsReadFile } from 'node:fs/promises';
import * as path from 'node:path';
import { makeFindingId, trimEvidence } from '../core/findings';
import { LineIndex, lineRange } from '../core/text';
import {
  severityRank,
  type Finding,
  type ResolvedDep,
  type Severity,
  type SourceRange,
} from '../core/types';

/** Lifecycle scripts npm runs automatically on install, with their base severity. */
const NPM_HOOKS: Record<string, Severity> = {
  preinstall: 'medium',
  install: 'medium',
  postinstall: 'medium',
  // Only runs for git/local installs, not registry tarballs.
  prepare: 'low',
};

/** Download-and-run, inline code, or encoded payloads inside a script. */
const DANGEROUS_SCRIPT =
  /\b(curl|wget|powershell|pwsh|iwr|Invoke-WebRequest|Invoke-Expression|certutil|bitsadmin)\b|\|\s*(sh|bash|zsh|node|python3?)\b|\bnode\s+-e\b|\bpython3?\s+-c\b|\beval\b|base64|https?:\/\//i;

const RISKY_PYTHON =
  /\b(os\.system|os\.popen|subprocess\.|urllib\.request|urlopen|requests\.(get|post)|socket\.|exec\s*\(|eval\s*\(|base64\.|marshal\.|__import__\s*\()/;

/** .pth files shipped by setuptools, virtualenv and editable installs. */
const KNOWN_PTH = [
  /^distutils-precedence\.pth$/,
  /^_virtualenv\.pth$/,
  /^__editable__.*\.pth$/,
  /-nspkg\.pth$/,
];

interface Ctx {
  dep: ResolvedDep;
  pkg: { ecosystem: ResolvedDep['ecosystem']; name: string; version: string };
}

function finding(
  ctx: Ctx,
  file: string,
  ruleId: string,
  title: string,
  severity: Severity,
  message: string,
  range: SourceRange,
  evidence: string,
): Finding {
  const rel = ctx.dep.installPath
    ? path.relative(ctx.dep.installPath, file).split(path.sep).join('/')
    : file;
  return {
    id: makeFindingId(ruleId, ctx.pkg, rel, range.startLine),
    ruleId,
    title,
    category: 'install-hook',
    severity,
    message,
    source: 'install-hook',
    package: ctx.pkg,
    location: { file, range },
    evidence: trimEvidence(evidence),
  };
}

function scanNpmManifest(ctx: Ctx, file: string, text: string, hasBindingGyp: boolean): Finding[] {
  const root = parseTree(text);
  if (!root) return [];
  const lines = new LineIndex(text);
  const out: Finding[] = [];
  let hasInstallScript = false;
  for (const [hook, base] of Object.entries(NPM_HOOKS)) {
    const node = findNodeAtLocation(root, ['scripts', hook]);
    if (!node || typeof node.value !== 'string') continue;
    if (hook !== 'prepare') hasInstallScript = true;
    const script = node.value;
    const dangerous = DANGEROUS_SCRIPT.test(script);
    const severity: Severity = dangerous ? 'critical' : base;
    out.push(
      finding(
        ctx,
        file,
        'install-hook/npm-lifecycle-script',
        dangerous ? 'Install script downloads or runs code' : 'Runs a script on install',
        severity,
        `${ctx.dep.name} runs "${hook}": ${trimEvidence(script, 120)}`,
        lines.range(node.offset, node.offset + node.length),
        script,
      ),
    );
  }
  if (hasBindingGyp && !hasInstallScript) {
    out.push(
      finding(
        ctx,
        file,
        'install-hook/npm-native-build',
        'Compiles native code on install',
        'low',
        `${ctx.dep.name} has binding.gyp, so npm runs node-gyp rebuild on install`,
        lineRange(0, lines.line(0).length),
        'binding.gyp',
      ),
    );
  }
  return out;
}

function scanSetupPy(ctx: Ctx, file: string, text: string): Finding[] {
  const lines = new LineIndex(text);
  for (let i = 0; i < lines.lineCount; i++) {
    const line = lines.line(i);
    if (/^\s*#/.test(line)) continue;
    const m = RISKY_PYTHON.exec(line) ?? /\bcmdclass\s*=/.exec(line);
    if (!m) continue;
    const risky = !m[0].startsWith('cmdclass');
    return [
      finding(
        ctx,
        file,
        'install-hook/python-setup-exec',
        risky ? 'setup.py runs commands or network code' : 'setup.py customizes install commands',
        risky ? 'high' : 'medium',
        `${ctx.dep.name} setup.py ${risky ? `uses ${m[0].trim()}` : 'overrides install commands (cmdclass)'}`,
        { startLine: i, startCol: m.index, endLine: i, endCol: m.index + m[0].length },
        line,
      ),
    ];
  }
  return [];
}

const RUST_NETWORK =
  /\b(reqwest|ureq|hyper|isahc|surf|curl)::|\bTcpStream::connect\b|\bUdpSocket::bind\b|\bdirs::home_dir\b|env::var(_os)?\(\s*"(HOME|USERPROFILE)"/;
const RUST_SHELL =
  /Command::new\(\s*"(\/bin\/)?(sh|bash|zsh|cmd(\.exe)?|powershell(\.exe)?|pwsh|curl|wget)"/;

/** Cargo runs a crate's build.rs on the developer's machine at build time. */
function scanBuildRs(ctx: Ctx, file: string, text: string): Finding[] {
  const lines = new LineIndex(text);
  let severity: Severity = 'low';
  let hit: { line: number; col: number; len: number; text: string } | undefined;
  for (let i = 0; i < lines.lineCount; i++) {
    const line = lines.line(i);
    if (/^\s*\/\//.test(line)) continue;
    const net = RUST_NETWORK.exec(line);
    const shell = net ? undefined : RUST_SHELL.exec(line);
    const m = net ?? shell;
    if (!m) continue;
    const level: Severity = net ? 'high' : 'medium';
    if (!hit || severityRank(level) > severityRank(severity)) {
      severity = level;
      hit = { line: i, col: m.index, len: m[0].length, text: line };
    }
  }
  const range = hit
    ? { startLine: hit.line, startCol: hit.col, endLine: hit.line, endCol: hit.col + hit.len }
    : lineRange(0, lines.line(0).length);
  return [
    finding(
      ctx,
      file,
      'install-hook/cargo-build-script',
      severity === 'low' ? 'Runs a build script' : 'Build script runs commands or network code',
      severity,
      severity === 'low'
        ? `${ctx.dep.name} has a build.rs that Cargo runs on your machine at build time`
        : `${ctx.dep.name} build.rs ${severity === 'high' ? 'uses the network or your home directory' : 'runs shell commands'} at build time`,
      range,
      hit?.text ?? 'build.rs',
    ),
  ];
}

/** Composer runs plugin packages during install/update; other dependency scripts never run. */
function scanComposerManifest(ctx: Ctx, file: string, text: string): Finding[] {
  const root = parseTree(text);
  const node = root ? findNodeAtLocation(root, ['type']) : undefined;
  if (node?.value !== 'composer-plugin') return [];
  const lines = new LineIndex(text);
  return [
    finding(
      ctx,
      file,
      'install-hook/composer-plugin',
      'Composer plugin runs during install',
      'medium',
      `${ctx.dep.name} is a Composer plugin, so its code runs during composer install and update`,
      lines.range(node.offset, node.offset + node.length),
      '"type": "composer-plugin"',
    ),
  ];
}

function scanPth(ctx: Ctx, file: string, text: string): Finding[] {
  const lines = new LineIndex(text);
  const known = KNOWN_PTH.some((re) => re.test(path.basename(file)));
  for (let i = 0; i < lines.lineCount; i++) {
    const line = lines.line(i);
    if (!/^\s*import[\s;]/.test(line)) continue;
    const risky = RISKY_PYTHON.test(line);
    const severity: Severity = risky ? 'critical' : known ? 'low' : 'high';
    return [
      finding(
        ctx,
        file,
        'install-hook/python-pth-exec',
        '.pth file runs code at interpreter startup',
        severity,
        `${ctx.dep.name} ships ${path.basename(file)}, which runs code every time Python starts`,
        lineRange(i, line.length),
        line,
      ),
    ];
  }
  return [];
}

/**
 * Detect code that runs automatically when a package is installed or imported by the
 * interpreter: npm lifecycle scripts, setup.py side effects and executable .pth files.
 */
export async function scanInstallHooks(
  dep: ResolvedDep,
  files: string[],
  readFile: (file: string) => Promise<string> = (f) => fsReadFile(f, 'utf8'),
): Promise<Finding[]> {
  const ctx: Ctx = { dep, pkg: { ecosystem: dep.ecosystem, name: dep.name, version: dep.version } };
  const out: Finding[] = [];
  for (const file of files) {
    const base = path.basename(file);
    const isRootManifest =
      dep.ecosystem === 'npm' &&
      base === 'package.json' &&
      dep.installPath !== undefined &&
      path.dirname(file) === dep.installPath;
    const isBuildScript =
      dep.ecosystem === 'cargo' &&
      dep.installPath !== undefined &&
      file === path.join(dep.installPath, 'build.rs');
    const isComposerManifest =
      dep.ecosystem === 'composer' &&
      base === 'composer.json' &&
      dep.installPath !== undefined &&
      path.dirname(file) === dep.installPath;
    const relevant =
      isRootManifest ||
      isBuildScript ||
      isComposerManifest ||
      (dep.ecosystem === 'pypi' && (base === 'setup.py' || base.endsWith('.pth')));
    if (!relevant) continue;
    let text: string;
    try {
      text = await readFile(file);
    } catch {
      continue;
    }
    if (isRootManifest) {
      const gyp = existsSync(path.join(dep.installPath as string, 'binding.gyp'));
      out.push(...scanNpmManifest(ctx, file, text, gyp));
    } else if (isBuildScript) out.push(...scanBuildRs(ctx, file, text));
    else if (isComposerManifest) out.push(...scanComposerManifest(ctx, file, text));
    else if (base === 'setup.py') out.push(...scanSetupPy(ctx, file, text));
    else out.push(...scanPth(ctx, file, text));
  }
  return out;
}
