import type { SourceRange } from './types';

/** Maps string offsets to zero-based line/column (UTF-16 units, like VS Code positions). */
export class LineIndex {
  private readonly starts: number[] = [0];

  constructor(readonly text: string) {
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) this.starts.push(i + 1);
    }
  }

  get lineCount(): number {
    return this.starts.length;
  }

  position(offset: number): { line: number; col: number } {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((this.starts[mid] as number) <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo, col: offset - (this.starts[lo] as number) };
  }

  range(start: number, end: number): SourceRange {
    const a = this.position(start);
    const b = this.position(end);
    return { startLine: a.line, startCol: a.col, endLine: b.line, endCol: b.col };
  }

  /** Text of a line without its trailing CR/LF. */
  line(n: number): string {
    const start = this.starts[n] ?? this.text.length;
    const next = this.starts[n + 1];
    const raw = this.text.slice(start, next === undefined ? undefined : next - 1);
    return raw.endsWith('\r') ? raw.slice(0, -1) : raw;
  }

  lineStart(n: number): number {
    return this.starts[n] ?? this.text.length;
  }
}

/** Range for a whole line, used for package-level diagnostics on a manifest line. */
export function lineRange(line: number, length: number): SourceRange {
  return { startLine: line, startCol: 0, endLine: line, endCol: length };
}
