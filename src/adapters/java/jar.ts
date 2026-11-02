import { createWriteStream, existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import * as yauzl from 'yauzl';

export interface ExtractOptions {
  include: (entryName: string) => boolean;
  maxEntries: number;
  maxEntryBytes: number;
  maxTotalBytes: number;
}

export const DEFAULT_EXTRACT: ExtractOptions = {
  include: (name) => name.endsWith('.java'),
  maxEntries: 5000,
  maxEntryBytes: 2 * 1024 * 1024,
  maxTotalBytes: 64 * 1024 * 1024,
};

const MARKER = '.depthreat-extracted';

/** Destination for an entry, or undefined if it would escape `destDir` (zip-slip). */
export function safeEntryPath(destDir: string, entryName: string): string | undefined {
  if (path.isAbsolute(entryName) || /^[a-zA-Z]:/.test(entryName) || entryName.includes('\0')) {
    return undefined;
  }
  const target = path.resolve(destDir, entryName);
  return target.startsWith(path.resolve(destDir) + path.sep) ? target : undefined;
}

function openZip(file: string): Promise<yauzl.ZipFile> {
  return new Promise((resolve, reject) =>
    yauzl.open(
      file,
      // decodeStrings: false keeps yauzl from aborting on hostile names; we validate them ourselves.
      { lazyEntries: true, autoClose: true, validateEntrySizes: true, decodeStrings: false },
      (err, zip) => (err || !zip ? reject(err ?? new Error('cannot open archive')) : resolve(zip)),
    ),
  );
}

function limitBytes(max: number): Transform {
  let seen = 0;
  return new Transform({
    transform(chunk: Buffer, _enc, done) {
      seen += chunk.length;
      done(seen > max ? new Error('entry too large') : null, chunk);
    },
  });
}

/**
 * Extract matching entries of a (sources) jar into `destDir`. Only reads the archive; nothing in
 * it is executed. Skips unsafe paths and oversized entries, and is a no-op when `destDir` was
 * already extracted. Returns the extracted file paths.
 */
export async function extractJar(
  jarPath: string,
  destDir: string,
  opts: ExtractOptions = DEFAULT_EXTRACT,
): Promise<{ files: string[]; skipped: number }> {
  const files: string[] = [];
  let skipped = 0;
  if (existsSync(path.join(destDir, MARKER))) return { files, skipped };
  await mkdir(destDir, { recursive: true });
  const zip = await openZip(jarPath);
  let total = 0;
  let entries = 0;
  await new Promise<void>((resolve, reject) => {
    zip.on('error', reject);
    zip.on('end', resolve);
    zip.on('entry', (entry: yauzl.Entry) => {
      const name = Buffer.isBuffer(entry.fileName)
        ? (entry.fileName as Buffer).toString('utf8')
        : entry.fileName;
      const target = safeEntryPath(destDir, name);
      const wanted = !name.endsWith('/') && opts.include(name);
      if (
        !wanted ||
        !target ||
        entry.uncompressedSize > opts.maxEntryBytes ||
        entries >= opts.maxEntries ||
        total + entry.uncompressedSize > opts.maxTotalBytes
      ) {
        if (wanted) skipped++;
        zip.readEntry();
        return;
      }
      entries++;
      total += entry.uncompressedSize;
      zip.openReadStream(entry, (err, stream) => {
        if (err || !stream) {
          skipped++;
          zip.readEntry();
          return;
        }
        mkdir(path.dirname(target), { recursive: true })
          .then(() => pipeline(stream, limitBytes(opts.maxEntryBytes), createWriteStream(target)))
          .then(() => files.push(target))
          .catch(() => skipped++)
          .finally(() => zip.readEntry());
      });
    });
    zip.readEntry();
  });
  await writeFile(path.join(destDir, MARKER), '');
  return { files: files.sort(), skipped };
}
