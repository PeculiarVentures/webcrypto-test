import assert from "assert";
import { Convert } from "pvtsutils";
import { createTestPlatform } from "./platform";
import type { ITestPlatform } from "./types";
import * as types from "./types";

async function importKey(crypto: Crypto, key: types.IImportKeyParams) {
  if (key.format === "jwk") {
    return crypto.subtle.importKey(
      key.format,
      key.data as JsonWebKey,
      key.algorithm,
      key.extractable,
      key.keyUsages,
    );
  }

  return crypto.subtle.importKey(
    key.format,
    key.data as BufferSource,
    key.algorithm,
    key.extractable,
    key.keyUsages,
  );
}

/**
 * Gets keys
 * @param crypto
 * @param key
 */
async function getKeys(crypto: Crypto, key: types.IImportKeyParams | types.IImportKeyPairParams) {
  const keys = {} as CryptoKeyPair;
  if ("privateKey" in key) {
    keys.privateKey = await importKey(crypto, key.privateKey);
    keys.publicKey = await importKey(crypto, key.publicKey);
  } else {
    keys.privateKey = keys.publicKey = await importKey(crypto, key);
  }
  return keys;
}

async function wrapTest(promise: () => Promise<void>, action: types.ITestAction, index: number, platform: ITestPlatform) {
  const test = action.skip
    ? platform.it.skip ?? platform.it
    : action.only
      ? platform.it.only ?? platform.it
      : platform.it;

  test(action.name || `#${index + 1}`, async () => {
    if (action.error) {
      await assert.rejects(promise(), action.error);
    } else {
      await promise();
    }
  });
}

function isKeyPair(obj: any): obj is CryptoKeyPair {
  return obj.privateKey && obj.publicKey;
}

function testGenerateKey(generateKey: types.ITestGenerateKeyAction[], crypto: Crypto, platform: ITestPlatform) {
  platform.describe("Generate Key", () => {
    generateKey.forEach((action, index) => {
      wrapTest(async () => {
        const algorithm = Object.assign({}, action.algorithm);
        algorithm.name = algorithm.name.toLowerCase();
        const key = await crypto.subtle.generateKey(algorithm as any, action.extractable, action.keyUsages) as CryptoKey | CryptoKeyPair;
        assert(key);
        if (!isKeyPair(key)) {
          const generatedKey = key as CryptoKey;
          assert.equal(generatedKey.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
          assert.equal(generatedKey.extractable, action.extractable);
          assert.deepEqual(generatedKey.usages, action.keyUsages);
        } else {
          const generatedKey = key;
          assert(generatedKey.privateKey);
          assert.equal(generatedKey.privateKey.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
          assert.equal(generatedKey.privateKey.extractable, action.extractable);
          assert(generatedKey.publicKey);
          assert.equal(generatedKey.publicKey.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
          assert.equal(generatedKey.publicKey.extractable, true);
        }
        action.assert?.(key);
      }, action, index, platform);
    });
  });
}

function testImport(importFn: types.ITestImportAction[], crypto: Crypto, platform: ITestPlatform) {
  platform.describe("Import/Export", () => {
    importFn.forEach((action, index) => {
      wrapTest(async () => {
        // @ts-ignore
        const importedKey = await crypto.subtle.importKey(action.format, action.data, action.algorithm, action.extractable, action.keyUsages);
        // Can't continue if key is not extractable.
        if (!action.extractable) {
          return;
        }
        const exportedData = await crypto.subtle.exportKey(action.format, importedKey);
        if (action.format === "jwk") {
          assert.deepEqual(exportedData, action.data);
        } else {
          assert.equal(Buffer.from(exportedData as ArrayBuffer).toString("hex"), Buffer.from(action.data as ArrayBuffer).toString("hex"));
        }
        action.assert?.(importedKey);
      }, action, index, platform);
    });
  });
}

function testSign(sign: types.ITestSignAction[], crypto: Crypto, platform: ITestPlatform) {
  platform.describe("Sign/Verify", () => {
    sign.forEach((action, index) => {
      wrapTest(async () => {
        // import keys
        const keys = await getKeys(crypto, action.key);
        const verifyKey = keys.publicKey;
        const signKey = keys.privateKey;
        const algorithm = Object.assign({}, action.algorithm);
        algorithm.name = algorithm.name.toLowerCase();
        // sign
        // @ts-ignore
        const signature = await crypto.subtle.sign(algorithm, signKey, action.data);
        // verify
        // @ts-ignore
        let ok = await crypto.subtle.verify(algorithm, verifyKey, signature, action.data);
        assert.equal(true, ok, "Cannot verify signature from Action data");
        // @ts-ignore
        ok = await crypto.subtle.verify(algorithm, verifyKey, action.signature, action.data);
        if (!ok) {
          assert.equal(Convert.ToHex(signature), Convert.ToHex(action.signature));
        }
        assert.equal(true, ok);
      }, action, index, platform);
    });
  });
}

function testDeriveBits(deriveBits: types.ITestDeriveBitsAction[], crypto: Crypto, platform: ITestPlatform) {
  platform.describe("Derive bits", () => {
    deriveBits.forEach((action, index) => {
      wrapTest(async () => {
        // import keys
        const keys = await getKeys(crypto, action.key);
        const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey }) as any;
        algorithm.name = algorithm.name.toLowerCase();
        // derive bits
        const derivedBits = await crypto.subtle.deriveBits(algorithm, keys.privateKey, action.length);
        assert.equal(Convert.ToHex(derivedBits), Convert.ToHex(action.data));
      }, action, index, platform);
    });
  });
}

function testDeriveKey(deriveKey: types.ITestDeriveKeyAction[], crypto: Crypto, platform: ITestPlatform) {
  platform.describe("Derive key", () => {
    deriveKey.forEach((action, index) => {
      wrapTest(async () => {
        // import keys
        const keys = await getKeys(crypto, action.key);
        const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey }) as any;
        algorithm.name = algorithm.name.toLowerCase();
        // derive key
        // @ts-ignore
        const derivedKey = await crypto.subtle.deriveKey(algorithm, keys.privateKey, action.derivedKeyType, true, action.keyUsages);
        const keyData = await crypto.subtle.exportKey(action.format, derivedKey);
        if (action.format === "jwk") {
          assert.deepEqual(keyData, action.keyData);
        } else {
          assert.equal(Convert.ToHex(keyData as ArrayBuffer), Convert.ToHex(action.keyData as ArrayBuffer));
        }
        action.assert?.(derivedKey);
      }, action, index, platform);
    });
  });
}

function testWrap(wrapKey: types.ITestWrapKeyAction[], crypto: Crypto, platform: ITestPlatform) {
  platform.describe("Wrap/Unwrap key", () => {
    wrapKey.forEach((action, index) => {
      wrapTest(async () => {
        const wKey = (await getKeys(crypto, action.wKey)).privateKey;
        const key = await getKeys(crypto, action.key);
        const wrappedKey = await crypto.subtle.wrapKey(action.wKey.format, wKey, key.publicKey, action.algorithm);
        if (action.wrappedKey) {
          assert.equal(Convert.ToHex(wrappedKey), Convert.ToHex(action.wrappedKey));
        }
        const unwrappedKey = await crypto.subtle.unwrapKey(action.wKey.format, wrappedKey, key.privateKey, action.algorithm, action.wKey.algorithm, action.wKey.extractable, action.wKey.keyUsages);
        assert.deepEqual(unwrappedKey.algorithm, wKey.algorithm);
      }, action, index, platform);
    });
  });
}

function testDigest(digest: types.ITestDigestAction[], crypto: Crypto, platform: ITestPlatform) {
  platform.describe("Digest", () => {
    digest.forEach((action, index) => {
      wrapTest(async () => {
        // @ts-ignore
        const hash = await crypto.subtle.digest(action.algorithm, action.data);
        assert.equal(Convert.ToHex(hash), Convert.ToHex(action.hash));
      }, action, index, platform);
    });
  });
}

function testEncrypt(encrypt: types.ITestEncryptAction[], crypto: Crypto, platform: ITestPlatform) {
  platform.describe("Encrypt/Decrypt", () => {
    encrypt.forEach((action, index) => {
      wrapTest(async () => {
        // import keys
        const keys = await getKeys(crypto, action.key);
        const encKey = keys.publicKey;
        const decKey = keys.privateKey;
        const algorithm = Object.assign({}, action.algorithm);
        algorithm.name = algorithm.name.toLowerCase();
        // encrypt
        // @ts-ignore
        const enc = await crypto.subtle.encrypt(algorithm, encKey, action.data);
        // decrypt
        let dec = await crypto.subtle.decrypt(algorithm, decKey, enc);
        assert.equal(Convert.ToHex(dec), Convert.ToHex(action.data));
        // @ts-ignore
        dec = await crypto.subtle.decrypt(algorithm, decKey, action.encData);
        assert.equal(Convert.ToHex(dec), Convert.ToHex(action.data));
      }, action, index, platform);
    });
  });
}

export function testCrypto(crypto: Crypto, param: types.ITestParams, platform?: Partial<ITestPlatform>) {
  const testPlatform = createTestPlatform(platform);

  testPlatform.describe(param.name, () => {
    if (param.actions.generateKey) {
      testGenerateKey(param.actions.generateKey, crypto, testPlatform);
    }

    if (param.actions.encrypt) {
      testEncrypt(param.actions.encrypt, crypto, testPlatform);
    }

    if (param.actions.import) {
      testImport(param.actions.import, crypto, testPlatform);
    }

    if (param.actions.sign) {
      testSign(param.actions.sign, crypto, testPlatform);
    }

    if (param.actions.deriveBits) {
      testDeriveBits(param.actions.deriveBits, crypto, testPlatform);
    }

    if (param.actions.deriveKey) {
      testDeriveKey(param.actions.deriveKey, crypto, testPlatform);
    }

    const digest = param.actions.digest;
    if (digest) {
      testDigest(digest, crypto, testPlatform);
    }

    const wrapKey = param.actions.wrapKey;
    if (wrapKey) {
      testWrap(wrapKey, crypto, testPlatform);
    }
  });
}