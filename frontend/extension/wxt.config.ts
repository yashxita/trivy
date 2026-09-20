import { defineConfig } from "wxt";

export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "Trivy",
    description:
      "Passive and active security scanning for the site you're browsing.",
    icons: {
      "16": "icon/16.png",
      "32": "icon/32.png",
      "48": "icon/48.png",
      "128": "icon/128.png",
    },
    permissions: [
      "activeTab",
      "storage",
      "webRequest",
      "downloads",
      "scripting",
      "cookies",
    ],
    host_permissions: ["<all_urls>"],
  },
});
