import type { InsecureCookieFinding } from "../../shared/types";

/**
 * Pure function: given the cookies chrome.cookies.getAll() returns for the
 * scanned domain, flags any missing Secure / HttpOnly / SameSite settings.
 * Called from background.ts, since only the background worker has the
 * "cookies" permission — a content script can only see document.cookie,
 * which excludes HttpOnly cookies entirely (the ones most worth checking).
 */
export function evaluateCookies(
  pageUrl: string,
  cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite?: string }[],
): InsecureCookieFinding[] {
  const findings: InsecureCookieFinding[] = [];

  for (const cookie of cookies) {
    const missingSecure = !cookie.secure;
    const missingHttpOnly = !cookie.httpOnly;
    const missingSameSite =
      !cookie.sameSite || cookie.sameSite.toLowerCase() === "no_restriction";

    if (!missingSecure && !missingHttpOnly && !missingSameSite) continue;

    const severity =
      missingSecure && missingHttpOnly ? "High" : "Medium";

    findings.push({
      category: "insecure_cookie",
      pageUrl,
      cookieName: cookie.name,
      missingSecure,
      missingHttpOnly,
      missingSameSite,
      severity,
    });
  }

  return findings;
}
