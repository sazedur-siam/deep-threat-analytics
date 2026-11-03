// Builds a throwaway copy of test/fixtures/vscode-extensions for unit and integration tests.
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

export const GLASSWORM_EXTENSION = 'glassworm-sample.color-theme-glow-1.0.3';
const MARKER = '/*GLASSWORM_PAYLOAD*/';

/** GlassWorm-style encoding: one invisible variation selector per byte. */
export function encodeInvisible(source: string): string {
  return String.fromCodePoint(
    ...[...Buffer.from(source)].map((b) => (b < 16 ? 0xfe00 + b : 0xe0100 + b - 16)),
  );
}

/**
 * Copy the fixture into `<tmp>/depthreat-ext-*\/[editorFolder/]extensions` (editors keep
 * extensions.json in a folder named `extensions`) and plant the invisible payload, so the
 * repository never contains raw invisible characters. Returns the new extensions folder.
 */
export async function makeExtensionsDir(fixtureDir: string, editorFolder = ''): Promise<string> {
  const base = await mkdtemp(path.join(tmpdir(), 'depthreat-ext-'));
  const dir = path.join(base, editorFolder, 'extensions');
  await mkdir(path.dirname(dir), { recursive: true });
  await cp(fixtureDir, dir, { recursive: true });
  const loader = path.join(dir, GLASSWORM_EXTENSION, 'lib', 'extension.js');
  const text = await readFile(loader, 'utf8');
  await writeFile(loader, text.replace(MARKER, encodeInvisible('console.log("fixture payload")')));
  return dir;
}
