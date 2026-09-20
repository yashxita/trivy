export interface CachedHeaders {
  pageUrl: string;
  headers: { name: string; value: string }[];
}

/**
 * Caches response headers per tab, keyed by tabId, captured via the
 * webRequest API. This is the only place headers are readable — a content
 * script cannot see its own page's response headers, so this cache is
 * what feeds the "security headers" check.
 *
 * Pulled out of background.ts into its own module because WXT's build
 * step statically parses entrypoint files to strip the wrapper function,
 * and its parser can't handle a generic type argument with an inline
 * object type (Map<number, { a: string; b: string }>) at the top level
 * of an entrypoint file. Plain modules like this one aren't parsed that
 * way, so this works fine here.
 */
const headerCacheByTab = new Map<number, CachedHeaders>();

export function setCachedHeaders(tabId: number, data: CachedHeaders): void {
  headerCacheByTab.set(tabId, data);
}

export function getCachedHeaders(tabId: number): CachedHeaders | undefined {
  return headerCacheByTab.get(tabId);
}
