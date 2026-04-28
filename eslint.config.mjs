import tseslint from "typescript-eslint";
import baseConfig from "@peculiar/eslint-config-base";

export default tseslint.config(
  ...baseConfig,
  {
    rules: {
      "@typescript-eslint/explicit-module-boundary-types": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/member-delimiter-style": "off",
      "@stylistic/quotes": "off",
      "@typescript-eslint/naming-convention": "off",
      "@typescript-eslint/unified-signatures": "off",
      "@typescript-eslint/no-extraneous-class": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      "@stylistic/padding-line-between-statements": "off",
      "@typescript-eslint/prefer-for-of": "off",
      "@stylistic/max-len": "off",
      "@stylistic/object-curly-newline": "off",
      "@stylistic/object-curly-spacing": "off",
      "@stylistic/spaced-comment": "off",
      "@stylistic/comma-dangle": "off",
      "@stylistic/eol-last": "off",
      "import/namespace": "off",
      "import/export": "off",
      "import/named": "off",
      "@typescript-eslint/ban-ts-comment": "off",
      "@stylistic/no-multiple-empty-lines": "off",
      "@stylistic/padded-blocks": "off",
      "@stylistic/operator-linebreak": "off",
      "import/no-unresolved": "off",
      "@typescript-eslint/no-require-imports": "off",
      "no-nested-ternary": "off",
      "no-undef": "off",
    },
  },
  {
    ignores: ["build/**/*"],
  },
);