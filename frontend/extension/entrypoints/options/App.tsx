import { useEffect, useState } from "react";
import { loadSettings, saveSettings } from "../../lib/settings";
import { DEFAULT_SETTINGS, type FindingCategory, type ScanSettings } from "../../shared/types";

// Only passive categories are user-toggleable — active-scan categories are
// produced entirely on the backend and aren't something the extension
// runs, so there's nothing to enable/disable here.
const TOGGLEABLE_CATEGORIES: { key: FindingCategory; label: string }[] = [
  { key: "header", label: "Security headers" },
  { key: "insecure_cookie", label: "Insecure cookies" },
  { key: "insecure_form", label: "Insecure forms" },
  { key: "unencrypted_credentials", label: "Unencrypted credential submission" },
  { key: "mixed_content", label: "Mixed HTTP/HTTPS content" },
  { key: "sensitive_url", label: "Sensitive info in URLs" },
  { key: "exposed_secret", label: "Exposed secrets / API keys" },
  { key: "vulnerable_library", label: "Vulnerable JS libraries" },
  { key: "sensitive_storage", label: "Sensitive data in storage" },
  { key: "dom_xss_taint", label: "DOM XSS taint tracking" },
  { key: "discovered_endpoint", label: "SPA endpoint discovery" },
];

export default function App() {
  const [settings, setSettings] = useState<ScanSettings>(DEFAULT_SETTINGS);
  const [newPath, setNewPath] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    loadSettings().then(setSettings);
  }, []);

  function persist(next: ScanSettings) {
    setSettings(next);
    saveSettings(next).then(() => {
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    });
  }

  function toggleCategory(key: FindingCategory) {
    persist({
      ...settings,
      enabledCategories: {
        ...settings.enabledCategories,
        [key]: settings.enabledCategories[key] === false ? true : false,
      },
    });
  }

  function isEnabled(key: FindingCategory) {
    return settings.enabledCategories[key] !== false;
  }

  function addExcludedPath() {
    if (!newPath.trim()) return;
    persist({
      ...settings,
      excludedPaths: [...settings.excludedPaths, newPath.trim()],
    });
    setNewPath("");
  }

  function removeExcludedPath(path: string) {
    persist({
      ...settings,
      excludedPaths: settings.excludedPaths.filter((p) => p !== path),
    });
  }

  return (
    <main className="options">
      <header className="options__header">
        <h1>Trivy settings</h1>
        {saved && <span className="saved-badge">Saved</span>}
      </header>

      <section className="glass-panel">
        <h2>Scan behavior</h2>
        <label className="field">
          <span>Default scan mode</span>
          <select
            value={settings.scanMode}
            onChange={(e) =>
              persist({ ...settings, scanMode: e.target.value as ScanSettings["scanMode"] })
            }
          >
            <option value="passive">Passive</option>
            <option value="active">Active</option>
            <option value="combined">Combined</option>
          </select>
        </label>

        <label className="field">
          <span>Requests per second (active scans)</span>
          <input
            type="number"
            min={1}
            max={20}
            value={settings.requestsPerSecond}
            onChange={(e) =>
              persist({ ...settings, requestsPerSecond: Number(e.target.value) })
            }
          />
        </label>

        <label className="field">
          <span>Max concurrency</span>
          <input
            type="number"
            min={1}
            max={10}
            value={settings.maxConcurrency}
            onChange={(e) =>
              persist({ ...settings, maxConcurrency: Number(e.target.value) })
            }
          />
        </label>

        <label className="field field--row">
          <span>Include session cookies in active scans</span>
          <input
            type="checkbox"
            checked={settings.includeSessionCookies}
            onChange={(e) =>
              persist({ ...settings, includeSessionCookies: e.target.checked })
            }
          />
        </label>
      </section>

      <section className="glass-panel">
        <h2>Excluded paths</h2>
        <p className="hint">
          Active scans will never touch these paths (e.g. logout, checkout, delete).
        </p>
        <div className="path-input-row">
          <input
            type="text"
            placeholder="/logout"
            value={newPath}
            onChange={(e) => setNewPath(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addExcludedPath()}
          />
          <button type="button" onClick={addExcludedPath}>Add</button>
        </div>
        <ul className="path-list">
          {settings.excludedPaths.map((path) => (
            <li key={path}>
              <span>{path}</span>
              <button type="button" onClick={() => removeExcludedPath(path)}>×</button>
            </li>
          ))}
        </ul>
      </section>

      <section className="glass-panel">
        <h2>Enabled checks</h2>
        <div className="category-grid">
          {TOGGLEABLE_CATEGORIES.map(({ key, label }) => (
            <label key={key} className="field field--row">
              <span>{label}</span>
              <input
                type="checkbox"
                checked={isEnabled(key)}
                onChange={() => toggleCategory(key)}
              />
            </label>
          ))}
        </div>
      </section>
    </main>
  );
}
