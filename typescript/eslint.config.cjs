const tseslint = require("@typescript-eslint/eslint-plugin");

module.exports = [
  { ignores: ["r2pipe/**/*.d.ts"] },
  ...tseslint.configs["flat/recommended"],
];
