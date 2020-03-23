import typescript from "rollup-plugin-typescript2";
import pkg from "./package.json";

const banner = [
  "/**",
  " * Copyright (c) 2020, Peculiar Ventures, All rights reserved.",
  " */",
  "",
].join("\n");
const input = "src/index.ts";
const external = Object.keys(pkg.dependencies);

export default {
  input,
  plugins: [
    typescript({
      check: true,
      clean: true,
      tsconfigOverride: {
        compilerOptions: {
          module: "ES2015",
        }
      }
    }),
  ],
  external: ["assert", ...external],
  output: [
    {
      banner,
      file: pkg.main,
      format: "cjs",
    }
  ],
};