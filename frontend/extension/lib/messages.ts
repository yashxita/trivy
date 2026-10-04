import type { Finding, ScanMode, ScanResponse } from "../shared/types";

/**
 * Every message that moves between content script <-> background <-> popup
 * is one of these. Per the report's trust-boundary section, the background
 * worker validates the `type` field and shape before acting on any message
 * — never trust a message just because it arrived on the right port.
 */

export type ExtensionMessage =
  | { type: "RUN_SCAN"; scanMode: ScanMode; consent: boolean }
  | { type: "CONTENT_FINDINGS"; findings: Finding[] }
  | { type: "SCAN_PROGRESS"; percent: number }
  | { type: "SCAN_COMPLETE"; result: ScanResponse }
  | { type: "SCAN_ERROR"; message: string; code?: string };

/** Narrow-and-validate helper — use instead of trusting `msg.type` blindly. */
export function isExtensionMessage(msg: unknown): msg is ExtensionMessage {
  if (typeof msg !== "object" || msg === null) return false;
  if (!("type" in msg)) return false;
  const validTypes: ExtensionMessage["type"][] = [
    "RUN_SCAN",
    "CONTENT_FINDINGS",
    "SCAN_PROGRESS",
    "SCAN_COMPLETE",
    "SCAN_ERROR",
  ];
  return validTypes.includes((msg as { type: string }).type as never);
}
