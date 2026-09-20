import { DEFAULT_SETTINGS, type ScanSettings } from "../shared/types";

/**
 * Single source of truth for where settings live in chrome.storage and how
 * to read/write them. Both the popup, the content script, the background
 * worker, and the options page all import from here so nothing reads or
 * writes a different key by accident.
 */
export const SETTINGS_STORAGE_KEY = "scanSettings";

export function loadSettings(): Promise<ScanSettings> {
  return new Promise((resolve) => {
    chrome.storage.local.get([SETTINGS_STORAGE_KEY], (result) => {
      resolve({ ...DEFAULT_SETTINGS, ...(result[SETTINGS_STORAGE_KEY] ?? {}) });
    });
  });
}

export function saveSettings(settings: ScanSettings): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [SETTINGS_STORAGE_KEY]: settings }, () => resolve());
  });
}
