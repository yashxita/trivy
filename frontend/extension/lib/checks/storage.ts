import type { SensitiveStorageFinding } from "../../shared/types";

const JWT_PATTERN = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const SENSITIVE_KEY_PATTERN = /token|password|secret|api[_-]?key|auth|session/i;

function scanStorage(
  storage: Storage,
  storageType: "localStorage" | "sessionStorage",
  pageUrl: string,
): SensitiveStorageFinding[] {
  const findings: SensitiveStorageFinding[] = [];

  for (let i = 0; i < storage.length; i++) {
    const key = storage.key(i);
    if (!key) continue;
    const value = storage.getItem(key) ?? "";

    let reason: string | null = null;
    if (JWT_PATTERN.test(value)) {
      reason = "value matches JWT pattern";
    } else if (SENSITIVE_KEY_PATTERN.test(key) && value.length > 0) {
      reason = "key name suggests a token or credential";
    }

    if (reason) {
      findings.push({
        category: "sensitive_storage",
        pageUrl,
        storageType,
        keyName: key,
        reason,
        severity: "Medium",
      });
    }
  }

  return findings;
}

export function checkSensitiveStorage(): SensitiveStorageFinding[] {
  const pageUrl = window.location.href;
  try {
    return [
      ...scanStorage(window.localStorage, "localStorage", pageUrl),
      ...scanStorage(window.sessionStorage, "sessionStorage", pageUrl),
    ];
  } catch {
    // Storage access can throw in some sandboxed/iframe contexts — fail closed.
    return [];
  }
}
