import type { CapturedRequest } from "../lib/requestCapture";

/**
 * Runs in the page's own JS context (world: "main"), not the isolated
 * content-script world, because that's the only place fetch/XHR calls
 * made by the page's own code (e.g. a Juice-Shop-style SPA) can actually
 * be observed — a normal isolated-world content script can't see them.
 *
 * MAIN-world scripts have no access to chrome.* APIs at all, so this
 * doesn't try to message the background directly. It just stores
 * sanitized templates on a page global; background.ts reads that global
 * back out with a one-off chrome.scripting.executeScript call when a
 * scan runs (see runScan() in background.ts).
 *
 * Known limitation: chrome.scripting world:"MAIN" injection is a Chrome
 * feature — Firefox support is inconsistent, so on Firefox this script
 * still runs (declared the same way) but background.ts's read-back step
 * may need a different approach there. Flagging this rather than
 * silently pretending cross-browser parity is solved.
 */
export default defineContentScript({
  matches: ["<all_urls>"],
  world: "MAIN",
  main() {
    const MAX_CAPTURED = 200;
    const captured: CapturedRequest[] = [];
    const dedupeKeys = new Set<string>();

    function queryParamNames(url: string): string[] {
      try {
        const u = new URL(url, window.location.href);
        const names: string[] = [];
        u.searchParams.forEach((_v, k) => {
          if (!names.includes(k)) names.push(k);
        });
        return names;
      } catch {
        return [];
      }
    }

    function bodyFieldNames(body: unknown, contentType: string): string[] {
      try {
        if (typeof body === "string" && contentType.includes("application/json")) {
          const parsed = JSON.parse(body);
          if (parsed && typeof parsed === "object") return Object.keys(parsed);
        }
        if (typeof body === "string" && contentType.includes("application/x-www-form-urlencoded")) {
          const names: string[] = [];
          new URLSearchParams(body).forEach((_v, k) => {
            if (!names.includes(k)) names.push(k);
          });
          return names;
        }
        if (typeof FormData !== "undefined" && body instanceof FormData) {
          const names: string[] = [];
          body.forEach((_v, k) => {
            if (!names.includes(k)) names.push(k);
          });
          return names;
        }
      } catch {
        // unparsable body — record the request with no field names rather than fail
      }
      return [];
    }

    function record(url: string, method: string, contentType: string, body: unknown) {
      if (captured.length >= MAX_CAPTURED) return;
      const queryParams = queryParamNames(url);
      const bodyFields = bodyFieldNames(body, contentType);
      const key = `${method}|${url.split("?")[0]}|${contentType}|${queryParams.join(",")}|${bodyFields.join(",")}`;
      if (dedupeKeys.has(key)) return;
      dedupeKeys.add(key);
      captured.push({
        url,
        method,
        contentType,
        queryParamNames: queryParams,
        bodyFieldNames: bodyFields,
      });
    }

    const originalFetch = window.fetch.bind(window);
    window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      try {
        const url =
          typeof input === "string"
            ? input
            : input instanceof URL
              ? input.href
              : input.url;
        const method = (
          init?.method ?? (input instanceof Request ? input.method : "GET")
        ).toUpperCase();
        const contentType =
          (init?.headers ? new Headers(init.headers).get("content-type") : null) ?? "";
        record(url, method, contentType, init?.body);
      } catch {
        // never let capture logic break the page's real request
      }
      return originalFetch(input as RequestInfo, init);
    }) as typeof window.fetch;

    const OriginalXHR = window.XMLHttpRequest;
    const originalOpen = OriginalXHR.prototype.open;
    const originalSetRequestHeader = OriginalXHR.prototype.setRequestHeader;
    const originalSend = OriginalXHR.prototype.send;

    OriginalXHR.prototype.open = function (
      this: XMLHttpRequest & { __trivyMethod?: string; __trivyUrl?: string; __trivyContentType?: string },
      method: string,
      url: string | URL,
      ...rest: unknown[]
    ) {
      this.__trivyMethod = method;
      this.__trivyUrl = typeof url === "string" ? url : url.href;
      // @ts-expect-error — forwarding the original variadic signature as-is
      return originalOpen.call(this, method, url, ...rest);
    };

    OriginalXHR.prototype.setRequestHeader = function (
      this: XMLHttpRequest & { __trivyContentType?: string },
      name: string,
      value: string,
    ) {
      if (name.toLowerCase() === "content-type") this.__trivyContentType = value;
      return originalSetRequestHeader.call(this, name, value);
    };

    OriginalXHR.prototype.send = function (
      this: XMLHttpRequest & {
        __trivyMethod?: string;
        __trivyUrl?: string;
        __trivyContentType?: string;
      },
      body?: Document | XMLHttpRequestBodyInit | null,
    ) {
      try {
        if (this.__trivyUrl) {
          record(this.__trivyUrl, this.__trivyMethod ?? "GET", this.__trivyContentType ?? "", body);
        }
      } catch {
        // never let capture logic break the page's real request
      }
      return originalSend.call(this, body);
    };

    (window as unknown as { __trivyCapturedRequests: CapturedRequest[] }).__trivyCapturedRequests =
      captured;
  },
});
