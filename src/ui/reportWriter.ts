import { mkdir, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import * as vscode from 'vscode';
import { CONFIG_DIR } from '../config/projectConfig';
import type { DepThreatSettings } from '../config/settings';
import type { ScanResult } from '../core/engine';
import { renderMarkdownReport } from '../report/markdown';

export const REPORT_FILE = 'report.md';

/** Default report location: `<workspace folder>/.depthreat/report.md`. */
export function defaultReportPath(folder: string): string {
  return path.join(folder, CONFIG_DIR, REPORT_FILE);
}

/** Render the scan as Markdown and write it to `file`, creating folders as needed. */
export async function writeReport(
  result: ScanResult,
  file: string,
  settings: DepThreatSettings,
  extensionVersion?: string,
): Promise<string> {
  const markdown = renderMarkdownReport(result, {
    generatedAt: new Date(),
    minSeverity: settings.minSeverity,
    relative: (p) => vscode.workspace.asRelativePath(p),
    ...(extensionVersion ? { extensionVersion } : {}),
  });
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, markdown);
  return file;
}
