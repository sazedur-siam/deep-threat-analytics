import { describe, expect, it } from 'vitest';
import { LineIndex, lineRange } from '../../src/core/text';

describe('LineIndex', () => {
  const idx = new LineIndex('ab\r\ncd\nef');

  it('maps offsets to line and column', () => {
    expect(idx.position(0)).toEqual({ line: 0, col: 0 });
    expect(idx.position(4)).toEqual({ line: 1, col: 0 });
    expect(idx.position(8)).toEqual({ line: 2, col: 1 });
    expect(idx.lineCount).toBe(3);
  });

  it('builds ranges across lines', () => {
    expect(idx.range(1, 5)).toEqual({ startLine: 0, startCol: 1, endLine: 1, endCol: 1 });
  });

  it('returns line text without line endings', () => {
    expect(idx.line(0)).toBe('ab');
    expect(idx.line(1)).toBe('cd');
    expect(idx.line(2)).toBe('ef');
    expect(idx.line(9)).toBe('');
    expect(idx.lineStart(1)).toBe(4);
    expect(idx.lineStart(9)).toBe(9);
  });

  it('makes whole-line ranges', () => {
    expect(lineRange(3, 5)).toEqual({ startLine: 3, startCol: 0, endLine: 3, endCol: 5 });
  });
});
