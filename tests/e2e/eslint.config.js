// Static checks for the dashboard sources (no build step, no framework).
// `no-undef` is the important rule: it catches helpers that were moved
// between modules but are still referenced, which would otherwise only fail
// at runtime in a rarely used code path.
const js = require("@eslint/js");
const globals = require("globals");

const shared = {
  ...js.configs.recommended.rules,
  "no-undef": "error",
  "no-unused-vars": ["warn", { args: "none", caughtErrors: "none" }],
  "no-empty": ["error", { allowEmptyCatch: true }],
};

module.exports = [
  {
    files: ["dashboard/boot.js"],
    languageOptions: { sourceType: "script", globals: { ...globals.browser } },
    rules: shared,
  },
  {
    files: ["dashboard/app.js", "dashboard/js/**/*.js"],
    languageOptions: { sourceType: "module", globals: { ...globals.browser } },
    rules: shared,
  },
];
