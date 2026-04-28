import type { ITestPlatform } from "./types";

function getGlobalTestPlatform() {
  const globalTests = globalThis as typeof globalThis & {
    describe?: ITestPlatform["describe"];
    it?: ITestPlatform["it"];
  };

  return {
    describe: globalTests.describe,
    it: globalTests.it,
  };
}

export function createTestPlatform(platform?: Partial<ITestPlatform>): ITestPlatform {
  const resolved = platform ?? getGlobalTestPlatform();

  if (!resolved.describe || !resolved.it) {
    throw new Error("WebcryptoTest requires a test platform. Pass { describe, it } or enable globals in your test runner.");
  }

  return {
    describe: resolved.describe,
    it: resolved.it,
  };
}