const typescript = require("@rollup/plugin-typescript");
const pkg = require("./package.json");

const startYear = 2020;
const currentYear = new Date().getFullYear();

const year
  = startYear === currentYear
    ? `${startYear}`
    : `${startYear}-${currentYear}`;

const banner = [
  "/**",
  ` * Copyright (c) ${year}, Peculiar Ventures`,
  " * SPDX-License-Identifier: MIT",
  " */",
  "",
].join("\n");
const input = "src/index.ts";
const external = Object.keys(pkg.dependencies || {});

module.exports = {
  input,
  plugins: [
    typescript({
      tsconfig: "./tsconfig.json",
      compilerOptions: {
        module: "ES2015",
      },
    }),
  ],
  external: ["assert", ...external],
  output: [
    {
      banner,
      file: pkg.main,
      format: "cjs",
    },
    {
      banner,
      file: pkg.module,
      format: "es",
    },
  ],
};