import { runContentScriptChecks } from "../lib/checks";
import { getDomTaintFindings, initDomTaintTracking } from "../lib/checks/domTaint";
import type { ExtensionMessage } from "../lib/messages";
import type { Finding } from "../shared/types";

export default defineContentScript({
  matches: ["<all_urls>"],
  main() {
    // Starts watching immediately on page load — DOM taint tracking has
    // to observe continuously (SPA route changes, ongoing DOM mutations),
    // not just at the moment a scan is triggered.
    initDomTaintTracking();

    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (
        typeof message === "object" &&
        message !== null &&
        "type" in message &&
        message.type === "REQUEST_CONTENT_FINDINGS"
      ) {
        runContentScriptChecks().then((findings) => {
          const combined: Finding[] = [...findings, ...getDomTaintFindings()];
          const response: ExtensionMessage = {
            type: "CONTENT_FINDINGS",
            findings: combined,
          };
          sendResponse(response);
        });
        return true;
      }
      return true;
    });
  },
});
