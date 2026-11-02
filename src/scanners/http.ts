export const USER_AGENT = 'deep-threat-analytics-vscode';
export const DEFAULT_TIMEOUT_MS = 15_000;

export interface OnlineOptions {
  /** Online lookups are opt-in; when false nothing is sent anywhere. */
  enabled: boolean;
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface JsonResponse<T> {
  status: number;
  body?: T;
}

/** GET/POST JSON with a timeout and fixed User-Agent. HTTP errors are returned, not thrown. */
export async function fetchJson<T>(
  url: string,
  opts: OnlineOptions,
  init: { method?: 'GET' | 'POST'; body?: unknown } = {},
): Promise<JsonResponse<T>> {
  const timeout = AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;
  const res = await (opts.fetchImpl ?? fetch)(url, {
    method: init.method ?? 'GET',
    headers: {
      'User-Agent': USER_AGENT,
      Accept: 'application/json',
      ...(init.body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
    signal,
  });
  if (!res.ok) return { status: res.status };
  return { status: res.status, body: (await res.json()) as T };
}

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.name === 'TimeoutError' ? 'request timed out' : e.message;
  return String(e);
}

/** A version that names one release (not a range, tag or "unknown"). */
export function isConcreteVersion(version: string): boolean {
  return /^v?\d+(\.\d+)*([-.+]?[0-9A-Za-z.+-]*)?$/.test(version);
}
