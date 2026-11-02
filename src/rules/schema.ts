import { z } from 'zod';
import { CATEGORIES, LANGUAGES, SEVERITIES } from '../core/types';

const regexString = z.string().refine(
  (src) => {
    try {
      new RegExp(src);
      return true;
    } catch {
      return false;
    }
  },
  { message: 'invalid regular expression' },
);

export const patternSchema = z.object({
  regex: regexString,
  /** Extra RegExp flags; 'g' and 'm' are managed by the scanner. Only 'i', 's', 'u' allowed. */
  flags: z
    .string()
    .regex(/^[isu]*$/, 'only i, s, u flags are allowed')
    .optional(),
});

export const matchSchema = z
  .object({
    /** Every pattern must match within the scope. */
    all: z.array(patternSchema).min(1).optional(),
    /** At least one pattern must match within the scope. */
    any: z.array(patternSchema).min(1).optional(),
    /** If any of these match within the scope, the rule does not fire. */
    not: z.array(patternSchema).optional(),
    /** Where all/any must co-occur: same line, same file, or anywhere in the package. */
    scope: z.enum(['line', 'file', 'package']).default('line'),
  })
  .refine((m) => m.all !== undefined || m.any !== undefined, {
    message: 'match needs at least one of "all" or "any"',
  });

export const ruleSchema = z.object({
  /** "<category-or-group>/<name>", lowercase kebab-case. */
  id: z
    .string()
    .regex(
      /^[a-z0-9-]+\/[a-z0-9-]+$/,
      'id must look like "group/rule-name" (lowercase, kebab-case)',
    ),
  title: z.string().min(1),
  category: z.enum(CATEGORIES),
  severity: z.enum(SEVERITIES),
  /** Languages the rule applies to; ['*'] for all. */
  languages: z.array(z.union([z.enum(LANGUAGES), z.literal('*')])).min(1),
  /** Optional basename globs restricting which files are checked (e.g. ["setup.py"]). */
  files: z.array(z.string()).optional(),
  match: matchSchema,
  /** Supports {package}, {version}, {file} placeholders. */
  message: z.string().min(1),
  references: z.array(z.string().url()).optional(),
  enabled: z.boolean().default(true),
});

export const ruleFileSchema = z.array(ruleSchema);

export type RuleInput = z.input<typeof ruleSchema>;
export type Rule = z.output<typeof ruleSchema>;
export type RulePattern = z.output<typeof patternSchema>;
