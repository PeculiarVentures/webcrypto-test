/**
 * Copyright (c) 2020, Peculiar Ventures, All rights reserved.
 */

'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var tslib = require('tslib');
var assert = _interopDefault(require('assert'));
var pvtsutils = require('pvtsutils');

function getKeys(crypto, key) {
    return tslib.__awaiter(this, void 0, void 0, function* () {
        const keys = {};
        if ("privateKey" in key) {
            keys.privateKey = yield crypto.subtle.importKey(key.privateKey.format, key.privateKey.data, key.privateKey.algorithm, key.privateKey.extractable, key.privateKey.keyUsages);
            keys.publicKey = yield crypto.subtle.importKey(key.publicKey.format, key.publicKey.data, key.publicKey.algorithm, key.publicKey.extractable, key.publicKey.keyUsages);
        }
        else {
            keys.privateKey = keys.publicKey = yield crypto.subtle.importKey(key.format, key.data, key.algorithm, key.extractable, key.keyUsages);
        }
        return keys;
    });
}
function wrapTest(promise, action, index) {
    return tslib.__awaiter(this, void 0, void 0, function* () {
        const test = action.skip
            ? it.skip
            : action.only
                ? it.only
                : it;
        test(action.name || `#${index + 1}`, () => tslib.__awaiter(this, void 0, void 0, function* () {
            if (action.error) {
                yield assert.rejects(promise(), action.error);
            }
            else {
                yield promise();
            }
        }));
    });
}
function isKeyPair(obj) {
    return obj.privateKey && obj.publicKey;
}
function testGenerateKey(generateKey, crypto) {
    context("Generate Key", () => {
        generateKey.forEach((action, index) => {
            wrapTest(() => tslib.__awaiter(this, void 0, void 0, function* () {
                const algorithm = Object.assign({}, action.algorithm);
                algorithm.name = algorithm.name.toLowerCase();
                const key = yield crypto.subtle.generateKey(algorithm, action.extractable, action.keyUsages);
                assert(key);
                if (!isKeyPair(key)) {
                    assert.equal(key.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
                    assert.equal(key.extractable, action.extractable);
                    assert.deepEqual(key.usages, action.keyUsages);
                }
                else {
                    assert(key.privateKey);
                    assert.equal(key.privateKey.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
                    assert.equal(key.privateKey.extractable, action.extractable);
                    assert(key.publicKey);
                    assert.equal(key.publicKey.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
                    assert.equal(key.publicKey.extractable, true);
                }
            }), action, index);
        });
    });
}
function testImport(importFn, crypto) {
    context("Import/Export", () => {
        importFn.forEach((action, index) => {
            wrapTest(() => tslib.__awaiter(this, void 0, void 0, function* () {
                const importedKey = yield crypto.subtle.importKey(action.format, action.data, action.algorithm, action.extractable, action.keyUsages);
                if (!action.extractable) {
                    return;
                }
                const exportedData = yield crypto.subtle.exportKey(action.format, importedKey);
                if (action.format === "jwk") {
                    assert.deepEqual(exportedData, action.data);
                }
                else {
                    assert.equal(Buffer.from(exportedData).toString("hex"), Buffer.from(action.data).toString("hex"));
                }
            }), action, index);
        });
    });
}
function testSign(sign, crypto) {
    context("Sign/Verify", () => {
        sign.forEach((action, index) => {
            wrapTest(() => tslib.__awaiter(this, void 0, void 0, function* () {
                const keys = yield getKeys(crypto, action.key);
                const verifyKey = keys.publicKey;
                const signKey = keys.privateKey;
                const algorithm = Object.assign({}, action.algorithm);
                algorithm.name = algorithm.name.toLowerCase();
                const signature = yield crypto.subtle.sign(algorithm, signKey, action.data);
                let ok = yield crypto.subtle.verify(algorithm, verifyKey, signature, action.data);
                assert.equal(true, ok, "Cannot verify signature from Action data");
                ok = yield crypto.subtle.verify(algorithm, verifyKey, action.signature, action.data);
                if (!ok) {
                    assert.equal(pvtsutils.Convert.ToHex(signature), pvtsutils.Convert.ToHex(action.signature));
                }
                assert.equal(true, ok);
            }), action, index);
        });
    });
}
function testDeriveBits(deriveBits, crypto) {
    context("Derive bits", () => {
        deriveBits.forEach((action, index) => {
            wrapTest(() => tslib.__awaiter(this, void 0, void 0, function* () {
                const keys = yield getKeys(crypto, action.key);
                const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey });
                algorithm.name = algorithm.name.toLowerCase();
                const derivedBits = yield crypto.subtle.deriveBits(algorithm, keys.privateKey, action.length);
                assert.equal(pvtsutils.Convert.ToHex(derivedBits), pvtsutils.Convert.ToHex(action.data));
            }), action, index);
        });
    });
}
function testDeriveKey(deriveKey, crypto) {
    context("Derive key", () => {
        deriveKey.forEach((action, index) => {
            wrapTest(() => tslib.__awaiter(this, void 0, void 0, function* () {
                const keys = yield getKeys(crypto, action.key);
                const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey });
                algorithm.name = algorithm.name.toLowerCase();
                const derivedKey = yield crypto.subtle.deriveKey(algorithm, keys.privateKey, action.derivedKeyType, true, action.keyUsages);
                const keyData = yield crypto.subtle.exportKey(action.format, derivedKey);
                if (action.format === "jwk") {
                    assert.deepEqual(keyData, action.keyData);
                }
                else {
                    assert.equal(pvtsutils.Convert.ToHex(keyData), pvtsutils.Convert.ToHex(action.keyData));
                }
            }), action, index);
        });
    });
}
function testWrap(wrapKey, crypto) {
    context("Wrap/Unwrap key", () => {
        wrapKey.forEach((action, index) => {
            wrapTest(() => tslib.__awaiter(this, void 0, void 0, function* () {
                const wKey = (yield getKeys(crypto, action.wKey)).privateKey;
                const key = yield getKeys(crypto, action.key);
                const wrappedKey = yield crypto.subtle.wrapKey(action.wKey.format, wKey, key.publicKey, action.algorithm);
                if (action.wrappedKey) {
                    assert.equal(pvtsutils.Convert.ToHex(wrappedKey), pvtsutils.Convert.ToHex(action.wrappedKey));
                }
                const unwrappedKey = yield crypto.subtle.unwrapKey(action.wKey.format, wrappedKey, key.privateKey, action.algorithm, action.wKey.algorithm, action.wKey.extractable, action.wKey.keyUsages);
                assert.deepEqual(unwrappedKey.algorithm, wKey.algorithm);
            }), action, index);
        });
    });
}
function testDigest(digest, crypto) {
    context("Digest", () => {
        digest.forEach((action, index) => {
            wrapTest(() => tslib.__awaiter(this, void 0, void 0, function* () {
                const hash = yield crypto.subtle.digest(action.algorithm, action.data);
                assert.equal(pvtsutils.Convert.ToHex(hash), pvtsutils.Convert.ToHex(action.hash));
            }), action, index);
        });
    });
}
function testEncrypt(encrypt, crypto) {
    context("Encrypt/Decrypt", () => {
        encrypt.forEach((action, index) => {
            wrapTest(() => tslib.__awaiter(this, void 0, void 0, function* () {
                const keys = yield getKeys(crypto, action.key);
                const encKey = keys.publicKey;
                const decKey = keys.privateKey;
                const algorithm = Object.assign({}, action.algorithm);
                algorithm.name = algorithm.name.toLowerCase();
                const enc = yield crypto.subtle.encrypt(algorithm, encKey, action.data);
                let dec = yield crypto.subtle.decrypt(algorithm, decKey, enc);
                assert.equal(pvtsutils.Convert.ToHex(dec), pvtsutils.Convert.ToHex(action.data));
                dec = yield crypto.subtle.decrypt(algorithm, decKey, action.encData);
                assert.equal(pvtsutils.Convert.ToHex(dec), pvtsutils.Convert.ToHex(action.data));
            }), action, index);
        });
    });
}
function testCrypto(crypto, param) {
    context(param.name, () => {
        if (param.actions.generateKey) {
            testGenerateKey(param.actions.generateKey, crypto);
        }
        if (param.actions.encrypt) {
            testEncrypt(param.actions.encrypt, crypto);
        }
        if (param.actions.import) {
            testImport(param.actions.import, crypto);
        }
        if (param.actions.sign) {
            testSign(param.actions.sign, crypto);
        }
        if (param.actions.deriveBits) {
            testDeriveBits(param.actions.deriveBits, crypto);
        }
        if (param.actions.deriveKey) {
            testDeriveKey(param.actions.deriveKey, crypto);
        }
        const digest = param.actions.digest;
        if (digest) {
            testDigest(digest, crypto);
        }
        const wrapKey = param.actions.wrapKey;
        if (wrapKey) {
            testWrap(wrapKey, crypto);
        }
    });
}

const AES128CBC = {
    name: "AES-128-CBC",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-CBC", length: 128 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-CBC",
                    iv: Buffer.from("1234567890abcdef"),
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("d5df3ea1598defe7446420802baef28e", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef"),
                    algorithm: { name: "AES-CBC" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef"),
                algorithm: "AES-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "wrong key size",
                error: Error,
                format: "raw",
                data: Buffer.from("12345678"),
                algorithm: "AES-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A128CBC",
                    k: "MTIzNDU2Nzg5MGFiY2RlZg",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
        wrapKey: [
            {
                key: {
                    format: "raw",
                    algorithm: "AES-CBC",
                    data: pvtsutils.Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg"),
                    extractable: true,
                    keyUsages: ["wrapKey", "unwrapKey"],
                },
                wKey: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef"),
                    algorithm: "AES-CBC",
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
                algorithm: {
                    name: "AES-CBC",
                    iv: Buffer.from("1234567890abcdef"),
                },
                wrappedKey: pvtsutils.Convert.FromHex("c630c4bf95977db13f386cc950b18e98521d54c4fda0ba15b2884d2695638bd9"),
            },
        ],
    }
};
const AES192CBC = {
    name: "AES-192-CBC",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-CBC", length: 192 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-CBC",
                    iv: Buffer.from("1234567890abcdef"),
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("67d0b3022149829bf009ad4aff19963a", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef12345678"),
                    algorithm: { name: "AES-CBC" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef12345678"),
                algorithm: "AES-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A192CBC",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    }
};
const AES256CBC = {
    name: "AES-256-CBC",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-CBC", length: 256 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-CBC",
                    iv: Buffer.from("1234567890abcdef"),
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("d827c1c6aee9f0f552c62f30ddee83af", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef1234567809abcdef"),
                    algorithm: { name: "AES-CBC" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef1234567890abcdef"),
                algorithm: "AES-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A256CBC",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    }
};

const AES128CTR = {
    name: "AES-128-CTR",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-CTR", length: 128 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-CTR",
                    counter: Buffer.from("1234567890abcdef"),
                    length: 128,
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("e1d561c49ce4eb2f448f8a00", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef"),
                    algorithm: { name: "AES-CTR" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef"),
                algorithm: "AES-CTR",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A128CTR",
                    k: "MTIzNDU2Nzg5MGFiY2RlZg",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-CTR",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    }
};
const AES192CTR = {
    name: "AES-192-CTR",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-CTR", length: 192 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-CTR",
                    counter: Buffer.from("1234567890abcdef"),
                    length: 128,
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("55a00e2851f00aba53bbd02c", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef12345678"),
                    algorithm: { name: "AES-CTR" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef12345678"),
                algorithm: "AES-CTR",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A192CTR",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-CTR",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    }
};
const AES256CTR = {
    name: "AES-256-CTR",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-CTR", length: 256 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-CTR",
                    counter: Buffer.from("1234567890abcdef"),
                    length: 128,
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("8208d011a20162c8af7a9ce5", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef1234567809abcdef"),
                    algorithm: { name: "AES-CTR" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef1234567890abcdef"),
                algorithm: "AES-CTR",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A256CTR",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-CTR",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    }
};

const AES128CMAC = {
    name: "AES-128-CMAC",
    only: true,
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-CMAC", length: 128 },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
        ],
        sign: [
            {
                algorithm: {
                    name: "AES-CMAC",
                    length: 256,
                },
                data: Buffer.from("test message"),
                signature: Buffer.from("98038e3ad7500d11005b6789c6cf9672", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef"),
                    algorithm: { name: "AES-CMAC" },
                    extractable: true,
                    keyUsages: ["sign", "verify"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef"),
                algorithm: "AES-CMAC",
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A128CMAC",
                    k: "MTIzNDU2Nzg5MGFiY2RlZg",
                    ext: true,
                    key_ops: ["sign", "verify"],
                },
                algorithm: "AES-CMAC",
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
        ],
    }
};
const AES192CMAC = {
    name: "AES-192-CMAC",
    only: true,
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-CMAC", length: 192 },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
        ],
        sign: [
            {
                algorithm: {
                    name: "AES-CMAC",
                    length: 192,
                },
                data: Buffer.from("test message"),
                signature: Buffer.from("fe5c107cbcafd8a0a47a83c7bf55f1d0", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef12345678"),
                    algorithm: { name: "AES-CMAC" },
                    extractable: true,
                    keyUsages: ["sign", "verify"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef12345678"),
                algorithm: "AES-CMAC",
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A192CMAC",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
                    ext: true,
                    key_ops: ["sign", "verify"],
                },
                algorithm: "AES-CMAC",
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
        ],
    }
};

const AES128GCM = {
    name: "AES-128-GCM",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-GCM", length: 128 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-GCM",
                    iv: Buffer.from("1234567890ab"),
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("68d645649ddf8152a253304d698185072f28cdcf7644ac6064bcb240", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef"),
                    algorithm: { name: "AES-GCM" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef"),
                algorithm: "AES-GCM",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A128GCM",
                    k: "MTIzNDU2Nzg5MGFiY2RlZg",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-GCM",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    }
};
const AES192GCM = {
    name: "AES-192-GCM",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-GCM", length: 192 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-GCM",
                    iv: Buffer.from("1234567890ab"),
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("d8eab579ed2418f41ca9c4567226f54cb391d3ca2cb6819dace35691", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef12345678"),
                    algorithm: { name: "AES-GCM" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef12345678"),
                algorithm: "AES-GCM",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A192GCM",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-GCM",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    }
};
const AES256GCM = {
    name: "AES-256-GCM",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-CTR", length: 256 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-GCM",
                    iv: Buffer.from("1234567890ab"),
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("f961f2aadbe689ffce86fcaf2619ab647950afcf19e55b71b857c79d", "hex"),
                key: {
                    format: "raw",
                    data: Buffer.from("1234567890abcdef1234567809abcdef"),
                    algorithm: { name: "AES-GCM" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef1234567890abcdef"),
                algorithm: "AES-GCM",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A256GCM",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-GCM",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    }
};

const AES128KW = {
    name: "AES-128-KW",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-KW", length: 128 },
                extractable: true,
                keyUsages: ["wrapKey", "unwrapKey"],
            },
        ],
        wrapKey: [
            {
                key: {
                    format: "raw",
                    algorithm: "AES-KW",
                    data: Buffer.from("000102030405060708090A0B0C0D0E0F", "hex"),
                    extractable: true,
                    keyUsages: ["wrapKey", "unwrapKey"],
                },
                wKey: {
                    format: "raw",
                    data: Buffer.from("00112233445566778899AABBCCDDEEFF", "hex"),
                    algorithm: "AES-KW",
                    extractable: true,
                    keyUsages: ["wrapKey", "unwrapKey"],
                },
                algorithm: {
                    name: "AES-KW",
                },
                wrappedKey: Buffer.from("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5", "hex"),
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef12345678"),
                algorithm: "AES-KW",
                extractable: true,
                keyUsages: ["wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A192KW",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
                    ext: true,
                    key_ops: ["wrapKey", "unwrapKey"],
                },
                algorithm: "AES-KW",
                extractable: true,
                keyUsages: ["wrapKey", "unwrapKey"],
            },
        ],
    },
};
const AES192KW = {
    name: "AES-192-KW",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-KW", length: 192 },
                extractable: true,
                keyUsages: ["wrapKey", "unwrapKey"],
            },
        ],
        wrapKey: [
            {
                key: {
                    format: "raw",
                    algorithm: "AES-KW",
                    data: Buffer.from("000102030405060708090A0B0C0D0E0F1011121314151617", "hex"),
                    extractable: true,
                    keyUsages: ["wrapKey", "unwrapKey"],
                },
                wKey: {
                    format: "raw",
                    data: Buffer.from("00112233445566778899AABBCCDDEEFF0001020304050607", "hex"),
                    algorithm: "AES-KW",
                    extractable: true,
                    keyUsages: ["wrapKey", "unwrapKey"],
                },
                algorithm: {
                    name: "AES-KW",
                },
                wrappedKey: Buffer.from("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2", "hex"),
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef12345678"),
                algorithm: "AES-KW",
                extractable: true,
                keyUsages: ["wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A192KW",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
                    ext: true,
                    key_ops: ["wrapKey", "unwrapKey"],
                },
                algorithm: "AES-KW",
                extractable: true,
                keyUsages: ["wrapKey", "unwrapKey"],
            },
        ],
    },
};
const AES256KW = {
    name: "AES-256-KW",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-KW", length: 256 },
                extractable: true,
                keyUsages: ["wrapKey", "unwrapKey"],
            },
        ],
        wrapKey: [
            {
                key: {
                    format: "raw",
                    algorithm: "AES-KW",
                    data: Buffer.from("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "hex"),
                    extractable: true,
                    keyUsages: ["wrapKey", "unwrapKey"],
                },
                wKey: {
                    format: "raw",
                    data: Buffer.from("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "hex"),
                    algorithm: "AES-KW",
                    extractable: true,
                    keyUsages: ["wrapKey", "unwrapKey"],
                },
                algorithm: {
                    name: "AES-KW",
                },
                wrappedKey: Buffer.from("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21", "hex"),
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef1234567890abcdef"),
                algorithm: "AES-KW",
                extractable: true,
                keyUsages: ["wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A256KW",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
                    ext: true,
                    key_ops: ["wrapKey", "unwrapKey"],
                },
                algorithm: "AES-KW",
                extractable: true,
                keyUsages: ["wrapKey", "unwrapKey"],
            },
        ],
    },
};

const AES128ECB = {
    name: "AES-128-ECB",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-ECB", length: 128 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-ECB",
                },
                data: pvtsutils.Convert.FromUtf8String("test message"),
                encData: pvtsutils.Convert.FromHex("c6ec2f91a9f48e10062ae41e86cb299f"),
                key: {
                    format: "raw",
                    data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
                    algorithm: { name: "AES-ECB" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
                algorithm: "AES-ECB",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A128ECB",
                    k: "MTIzNDU2Nzg5MGFiY2RlZg",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-ECB",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
        wrapKey: [
            {
                key: {
                    format: "raw",
                    algorithm: "AES-ECB",
                    data: pvtsutils.Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg"),
                    extractable: true,
                    keyUsages: ["wrapKey", "unwrapKey"],
                },
                wKey: {
                    format: "raw",
                    data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
                    algorithm: "AES-ECB",
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
                algorithm: {
                    name: "AES-ECB",
                },
                wrappedKey: pvtsutils.Convert.FromHex("039ec14b350bd92efd02dac2c01cdee6ea9953cfbdc067f20f5f47bb4459da79"),
            },
        ],
    },
};
const AES192ECB = {
    name: "AES-192-ECB",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-ECB", length: 192 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-ECB",
                },
                data: pvtsutils.Convert.FromUtf8String("test message"),
                encData: pvtsutils.Convert.FromHex("8c9f297827ad6aaa9e7501e79fb45ca5"),
                key: {
                    format: "raw",
                    data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
                    algorithm: { name: "AES-ECB" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
                algorithm: "AES-ECB",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A192ECB",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-ECB",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    },
};
const AES256ECB = {
    name: "AES-256-ECB",
    actions: {
        generateKey: [
            {
                algorithm: { name: "AES-ECB", length: 256 },
                extractable: true,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "AES-ECB",
                },
                data: pvtsutils.Convert.FromUtf8String("test message"),
                encData: pvtsutils.Convert.FromHex("84ccef71a364b112eb2b3b8b99587a95"),
                key: {
                    format: "raw",
                    data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567809abcdef"),
                    algorithm: { name: "AES-ECB" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567890abcdef"),
                algorithm: "AES-ECB",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "A256ECB",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "AES-ECB",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    },
};

const RSAPSS = {
    name: "RSA-PSS",
    actions: {
        generateKey: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
            return {
                name: hash,
                algorithm: {
                    name: "RSA-PSS",
                    hash,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    modulusLength: 1024,
                },
                extractable: false,
                keyUsages: ["sign", "verify"],
            };
        }),
        sign: [
            {
                algorithm: {
                    name: "RSA-PSS",
                    saltLength: 64,
                },
                data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
                signature: pvtsutils.Convert.FromBase64("OYz/7fv71ELOs5kuz5IiYq1NsXuOazl22xqIFjiY++hYFzJMWaR+ZI0WPoMOifvb1PNKmdQ4dY+QbpYC1vdzlAKfkLe22l5htLyQaXzjD/yeMZYrL0KmrabC9ayL6bxrMW+ccePStkbrF1Jn0LT09l22aX/r1y3SPrl0b+zwo/Q="),
                key: {
                    publicKey: {
                        format: "jwk",
                        algorithm: { name: "RSA-PSS", hash: "SHA-256" },
                        data: {
                            alg: "PS256",
                            e: "AQAB",
                            ext: true,
                            key_ops: ["verify"],
                            kty: "RSA",
                            n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                        },
                        extractable: true,
                        keyUsages: ["verify"],
                    },
                    privateKey: {
                        format: "jwk",
                        algorithm: { name: "RSA-PSS", hash: "SHA-256" },
                        data: {
                            alg: "PS256",
                            d: "AkeIWJywp9OfYsj0ECsKmhDVBw55ZL_yU-rbIrashQ_31P6gsc_0I-SVN1rd8Hz79OJ_rTY8ZRBZ4PIyFdPoyvuo5apHdAHH6riJKxDHWPxhE-ReNVEPSTiF1ry8DSe5zC7w9BLnH_QM8bkN4cOnvgqrg7EbrGWomAGJVvoRwOM",
                            dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
                            dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
                            e: "AQAB",
                            ext: true,
                            key_ops: ["sign"],
                            kty: "RSA",
                            n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                            p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
                            q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
                            qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
                        },
                        extractable: true,
                        keyUsages: ["sign"],
                    },
                },
            },
        ],
    },
};

const RSAOAEP = {
    name: "RSA-OAEP",
    actions: {
        generateKey: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
            return {
                name: hash,
                algorithm: {
                    name: "RSA-OAEP",
                    hash,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    modulusLength: 1024,
                },
                extractable: false,
                keyUsages: ["encrypt", "decrypt"],
            };
        }),
        encrypt: [
            {
                name: "with label",
                algorithm: {
                    name: "RSA-OAEP",
                    label: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
                },
                data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
                encData: pvtsutils.Convert.FromBase64("aHu8PBZuctYecfINKgUdB8gBoLyUUFxTZDTzTHUk9KKxtYywYml48HoijBG5DyaIWUUbOIdPgap9C8pFG2iYShQnE9Aj3gzKLHacBbFw1P79+Ei/Tm0j/THiXqCplBZC4dIp4jhTDepmdrlXZcY0slmjG+h8h8TpSmWKP3pEGGk="),
                key: {
                    publicKey: {
                        format: "jwk",
                        algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
                        data: {
                            alg: "RSA-OAEP-256",
                            e: "AQAB",
                            ext: true,
                            key_ops: ["encrypt"],
                            kty: "RSA",
                            n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                        },
                        extractable: true,
                        keyUsages: ["encrypt"],
                    },
                    privateKey: {
                        format: "jwk",
                        algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
                        data: {
                            alg: "RSA-OAEP-256",
                            d: "AkeIWJywp9OfYsj0ECsKmhDVBw55ZL_yU-rbIrashQ_31P6gsc_0I-SVN1rd8Hz79OJ_rTY8ZRBZ4PIyFdPoyvuo5apHdAHH6riJKxDHWPxhE-ReNVEPSTiF1ry8DSe5zC7w9BLnH_QM8bkN4cOnvgqrg7EbrGWomAGJVvoRwOM",
                            dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
                            dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
                            e: "AQAB",
                            ext: true,
                            key_ops: ["decrypt"],
                            kty: "RSA",
                            n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                            p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
                            q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
                            qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
                        },
                        extractable: true,
                        keyUsages: ["decrypt"],
                    },
                },
            },
            {
                name: "without label",
                algorithm: {
                    name: "RSA-OAEP",
                },
                data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
                encData: pvtsutils.Convert.FromBase64("NcsyyVE/y4Z1K5bWGElWAkvlN+jWpfgPtcytlydWUUz4RqFeW5w6KA1cQMHy3eNh920YXDjsLSYHe6Dz1CEqjIKkHS9HBuOhLA39yUArOu/fmn1lMnwb9N9roTxHDxpgY3y98DXEVkAKU4Py0rlzJLVazDV/+1YcbzFLCSKUNaI="),
                key: {
                    publicKey: {
                        format: "jwk",
                        algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
                        data: {
                            alg: "RSA-OAEP-256",
                            e: "AQAB",
                            ext: true,
                            key_ops: ["encrypt"],
                            kty: "RSA",
                            n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                        },
                        extractable: true,
                        keyUsages: ["encrypt"],
                    },
                    privateKey: {
                        format: "jwk",
                        algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
                        data: {
                            alg: "RSA-OAEP-256",
                            d: "AkeIWJywp9OfYsj0ECsKmhDVBw55ZL_yU-rbIrashQ_31P6gsc_0I-SVN1rd8Hz79OJ_rTY8ZRBZ4PIyFdPoyvuo5apHdAHH6riJKxDHWPxhE-ReNVEPSTiF1ry8DSe5zC7w9BLnH_QM8bkN4cOnvgqrg7EbrGWomAGJVvoRwOM",
                            dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
                            dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
                            e: "AQAB",
                            ext: true,
                            key_ops: ["decrypt"],
                            kty: "RSA",
                            n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                            p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
                            q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
                            qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
                        },
                        extractable: true,
                        keyUsages: ["decrypt"],
                    },
                },
            },
        ],
    },
};

const RSAESPKCS1 = {
    name: "RSAES-PKCS1-v1_5",
    actions: {
        generateKey: [
            {
                algorithm: {
                    name: "RSAES-PKCS1-v1_5",
                    publicExponent: new Uint8Array([1, 0, 1]),
                    modulusLength: 1024,
                },
                extractable: false,
                keyUsages: ["encrypt", "decrypt"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "RSAES-PKCS1-v1_5",
                },
                data: pvtsutils.Convert.FromHex("01435e62ad3ec4850720e34f8cab620e203749f2315b203d"),
                encData: pvtsutils.Convert.FromHex("76e5ea6e1df52471454f790923f60e2baa7adf5017fe0a36c0af3e32f6390d570e1d592375ba6035fdf4ffa70764b797ab54d0ab1efe89cf31d7fc98240a4d08c2476b7eb4c2d92355b8bf60e3897c3fcbfe09f20c7b159d9a9c4a6b2ce5021dd313e492afa762c24930f97f03a429f7b2b1e1d6088651d60e323835807c6fefe7952f74e5da29e8e327ea46e69a0a6684272f022bf18ec602ffcd10a62666b35a51ec7c7d101096f663ddfa0924a86bdbcde0433b4f71dc42bfd9facf329558026f8667f1a71c3365e09843a12339d8aaf31987b0d800e53fd0835e990096cb145e278153faf1188cd5713c6fcd289cb77d80515e1d200139b8ccac4d3bcebc"),
                key: {
                    publicKey: {
                        format: "jwk",
                        algorithm: { name: "RSAES-PKCS1-v1_5" },
                        data: {
                            alg: "RS1",
                            e: "AQAB",
                            ext: true,
                            key_ops: ["encrypt"],
                            kty: "RSA",
                            n: "xr8ELXq5dGFycys8jrc8vVPkWl2GzuRgyOxATtjcNIy5MD7j1XVsUH62VVdIVUUGt0IQ7K288ij3gkIPcIkRO6GmV0vbQAqHrjSHYUAtKQXbIgNRIuJGZvO5AXsxSo1X-tfhOxe140pseOkaehz1bGduhdcYWNR3xLmp7i-GQTRDo-v6CQXtFvSUwG_EIOXnl1trN2Q1Yw4wA1dbtY9FDz69uH-dEWTx7BFCAXVTQMjNe7BTvgGeQcX7XZIw5e2pd0pXjdIgb0xMgziwmc5bbABrGlhK7TmKqA47RlWzY_Lcj7VcTUfMfh7YKKichGTUbqxlgsRTma_e-0-vgDEz6w",
                        },
                        extractable: true,
                        keyUsages: ["encrypt"],
                    },
                    privateKey: {
                        format: "jwk",
                        algorithm: { name: "RSAES-PKCS1-v1_5" },
                        data: {
                            kty: "RSA",
                            alg: "RS1",
                            key_ops: ["decrypt"],
                            ext: true,
                            n: "xr8ELXq5dGFycys8jrc8vVPkWl2GzuRgyOxATtjcNIy5MD7j1XVsUH62VVdIVUUGt0IQ7K288ij3gkIPcIkRO6GmV0vbQAqHrjSHYUAtKQXbIgNRIuJGZvO5AXsxSo1X-tfhOxe140pseOkaehz1bGduhdcYWNR3xLmp7i-GQTRDo-v6CQXtFvSUwG_EIOXnl1trN2Q1Yw4wA1dbtY9FDz69uH-dEWTx7BFCAXVTQMjNe7BTvgGeQcX7XZIw5e2pd0pXjdIgb0xMgziwmc5bbABrGlhK7TmKqA47RlWzY_Lcj7VcTUfMfh7YKKichGTUbqxlgsRTma_e-0-vgDEz6w",
                            e: "AQAB",
                            d: "kZ2IoQ3G7UcshMdL8kC85vadW7wktldLtkqqf1qSVIo6cOfTJCWJe5yrWPG_VIJjfkeQgOh2hHKRjcV67HfwwWEZr-IrPMu6R1_DRPSxYdohiNUnUEi7TlkJ1tT882OF74rWQeaIZIS13wzjUk7_XjKWHsfO1d6t9dwWbiYx1nj4syQCcUrvHIgVXCfL85Tyu3NHqpxOdbzRb2OLmkv5ciHFExm4ai98xAgsEXbNvZQeSOOfKNsiCb-NjBXLYrbaDIsakAEV75893JubfeD51UHn7dPT8M8MmKEvrTOKCscShf01scTDHfx_hiOXK3XG4tVx9l2YGEkt3xCedljocQ",
                            p: "_dWMJ57SECcBbOjPRCvT97ypDyw9ydvnSZXTsn9c7ScxvUxBk6-wuMtgsLI8OWkhZGDBLyVrn-I3RMAN-A5QI_adoGdK7fq5lFWmQYvb1u1xUaGEInVFsM3BW7RBBF8N7OzHwULEQLTXb4jkpgwyCynsX0OEbVVvVerqrcr7osM",
                            q: "yHEjuQe9TNo-leMrL6cu-yDPfA85M8xQuBM59Cwz06-ggBRi9EOpbV-CrejGUbVlE9QmKGqIBT8C3NVBQwybzlgUihgIpnVgkb01lLEf13ohQ_GWV1mS8ybznjMgaVtVF5Lva4WixIDlXbOu4svVQpkr-KRpKvEMUCTsX-Sxx7k",
                            dp: "jMP4TaCN7dczuyoAh1Wm3yQIvRlTyrXgtbYZCEwJRJsPwmKfmz87Sb-_hz3QmCXtFrVxbKvb23agH8hB9uY5GziQgXvG2eLJN7Gn2YGuEKrsxNBFbraKR1pTeH-l7r6oAlPtEwfrvdaMApZv9oWc2wQMyWev8NIIRCVar7Z5hfE",
                            dq: "wi2g3sJZp9cRpGEDWFHM2KnrdxLEZqK7W-f8T8h2mM9eXFXjmyDlRLivP0zuuv9QoUn3gVXa2cI2QrsxUwQm-Fop47Hux1uUpvs2qgqBf1yoV0r2Sz7Sdk442fxLnOVG5OSKno5Cpbz89q54cOvoeHEswN59p4UHWai7eRZzB7k",
                            qi: "k9hlEyvZCWj8Fvxrknj5WHgaLrSqaVku3PVod2wUJox3aZ8vUsGmmD27lfiWwVKNRmgxLiazY40pLPu07SEmlJgF8QjzDb33k5Pcn9wRuezcCi-53LBRK6-EptZ-UjEINBlM_Cx_WOuxs7P77pwcCo2NV76ilxP5PP_34SUZ0ts",
                        },
                        extractable: true,
                        keyUsages: ["decrypt"],
                    },
                },
            },
        ],
    },
};

const RSASSAPKCS1 = {
    name: "RSASSA-PKCS1-v1_5",
    actions: {
        generateKey: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
            return {
                name: hash,
                algorithm: {
                    name: "RSASSA-PKCS1-v1_5",
                    hash,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    modulusLength: 1024,
                },
                extractable: false,
                keyUsages: ["sign", "verify"],
            };
        }),
        sign: [
            {
                algorithm: {
                    name: "RSASSA-PKCS1-v1_5",
                },
                data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
                signature: pvtsutils.Convert.FromBase64("f8OvbYnwX5YPVPjWkOTalYTFJjS1Ks7iNmPdLEby/kK6BEGk5uPvY/ebcok6sTQpQXJXJFJbOcMrZftmJXpm1szcgOdNgVW6FDc3722a9Mzvk/YfvNUCQRNEMON9lYKdpOLSXAFpXR5ovZytbFQ2w2ztpKkJvNY2QZQlizcZKSg="),
                key: {
                    publicKey: {
                        format: "jwk",
                        algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                        data: {
                            alg: "RS256",
                            e: "AQAB",
                            ext: true,
                            key_ops: ["verify"],
                            kty: "RSA",
                            n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                        },
                        extractable: true,
                        keyUsages: ["verify"],
                    },
                    privateKey: {
                        format: "jwk",
                        algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                        data: {
                            alg: "RS256",
                            d: "AkeIWJywp9OfYsj0ECsKmhDVBw55ZL_yU-rbIrashQ_31P6gsc_0I-SVN1rd8Hz79OJ_rTY8ZRBZ4PIyFdPoyvuo5apHdAHH6riJKxDHWPxhE-ReNVEPSTiF1ry8DSe5zC7w9BLnH_QM8bkN4cOnvgqrg7EbrGWomAGJVvoRwOM",
                            dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
                            dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
                            e: "AQAB",
                            ext: true,
                            key_ops: ["sign"],
                            kty: "RSA",
                            n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                            p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
                            q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
                            qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
                        },
                        extractable: true,
                        keyUsages: ["sign"],
                    },
                },
            },
        ],
        import: [
            {
                name: "public key JWK",
                format: "jwk",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                data: {
                    alg: "RS256",
                    e: "AQAB",
                    ext: true,
                    key_ops: ["verify"],
                    kty: "RSA",
                    n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "public key SPKI",
                format: "spki",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                data: pvtsutils.Convert.FromBase64("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+qm93G7JnqspidZOP9nMMEVkAACWl7mGmiJgepraPmQru/xTkRo9jZsuJv2bgHjSP6fcVX3FQIaKmVZ2owkkpP7g+MY7kTdLg32SMWG7nuehhPvPvfTYnSwld6gVtfGWAT7gbnk7GWbnYgPb9El6w/mfNwZOuJDChFusk/k4S3QIDAQAB"),
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "private key JWK",
                format: "jwk",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                data: {
                    alg: "RS256",
                    d: "AkeIWJywp9OfYsj0ECsKmhDVBw55ZL_yU-rbIrashQ_31P6gsc_0I-SVN1rd8Hz79OJ_rTY8ZRBZ4PIyFdPoyvuo5apHdAHH6riJKxDHWPxhE-ReNVEPSTiF1ry8DSe5zC7w9BLnH_QM8bkN4cOnvgqrg7EbrGWomAGJVvoRwOM",
                    dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
                    dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
                    e: "AQAB",
                    ext: true,
                    key_ops: ["sign"],
                    kty: "RSA",
                    n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                    p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
                    q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
                    qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "private key pkcs8",
                format: "pkcs8",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                data: pvtsutils.Convert.FromBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL6qb3cbsmeqymJ1k4/2cwwRWQAAJaXuYaaImB6mto+ZCu7/FORGj2Nmy4m/ZuAeNI/p9xVfcVAhoqZVnajCSSk/uD4xjuRN0uDfZIxYbue56GE+8+99NidLCV3qBW18ZYBPuBueTsZZudiA9v0SXrD+Z83Bk64kMKEW6yT+ThLdAgMBAAECgYACR4hYnLCn059iyPQQKwqaENUHDnlkv/JT6tsitqyFD/fU/qCxz/Qj5JU3Wt3wfPv04n+tNjxlEFng8jIV0+jK+6jlqkd0AcfquIkrEMdY/GET5F41UQ9JOIXWvLwNJ7nMLvD0Eucf9AzxuQ3hw6e+CquDsRusZaiYAYlW+hHA4wJBAOoxbZgSSUBSJUFF12WCILx+9GPWtN6Fiozbhdr3m+WX9PRLSzRPOjaZyJuOtzp6ByT1tJvMBxV2WX3GFUyD0f8CQQDQa20MyXWQjNJXas3MZek5Ly1SqvkvPQS1VnAhv0Yk8yYnQ/eBnzTXMSBlnj56xTtwtR/4FJkQCZ+coDzQbaMjAkEApOolqL7HwnmWLn7GDX8zGkm0Q1IAj+ouBL7ZZbaTm3wETLtwu+dGsQheEdzP/mfL/CTiCAwGuQBcSItimD0DdQJAFTSY59AnkgmB7TsErWNBE3xlVB/pMpE2xWyCBCz96gyDOUOFDz8vlSV+clhjawJeRd1n30nZOPSBtOHozhwZmQJAFByTxX4G2eXkk1xe0IuiEv7I5NS+CnFyp8iB4XLG0rabnfcIZFKpf//X0sNyVOAVo5+jJMuUYjCRTdaXNAWhkg=="),
                extractable: true,
                keyUsages: ["sign"],
            },
        ],
    },
};

const DESCBC = {
    name: "DES-CBC",
    actions: {
        generateKey: [
            {
                algorithm: { name: "DES-CBC", length: 64 },
                extractable: false,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "DES-CBC",
                    iv: Buffer.from("12345678"),
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("3af3f901ff01fe0102dfbbf37d9bdb94", "hex"),
                key: {
                    format: "raw",
                    algorithm: { name: "DES-CBC" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                    data: Buffer.from("12345678"),
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("12345678"),
                algorithm: "DES-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "DES-CBC",
                    k: "MTIzNDU2Nzg",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "DES-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    },
};

const DESEDE3CBC = {
    name: "DES-EDE3-CBC",
    actions: {
        generateKey: [
            {
                algorithm: { name: "DES-EDE3-CBC", length: 192 },
                extractable: false,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
        encrypt: [
            {
                algorithm: {
                    name: "DES-EDE3-CBC",
                    iv: Buffer.from("12345678"),
                },
                data: Buffer.from("test message"),
                encData: Buffer.from("b9ef20e7db926490e4ff8680d99d2141", "hex"),
                key: {
                    format: "raw",
                    algorithm: { name: "DES-EDE3-CBC" },
                    extractable: true,
                    keyUsages: ["encrypt", "decrypt"],
                    data: Buffer.from("1234567890abcdef12345678"),
                },
            },
        ],
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("1234567890abcdef12345678"),
                algorithm: "DES-EDE3-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "wrong key size",
                error: Error,
                format: "raw",
                data: Buffer.from("12345678"),
                algorithm: "DES-EDE3-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            {
                name: "jwk",
                format: "jwk",
                data: {
                    kty: "oct",
                    alg: "3DES-CBC",
                    k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
                    ext: true,
                    key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                },
                algorithm: "DES-EDE3-CBC",
                extractable: true,
                keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
        ],
    },
};

const ECDH = {
    name: "ECDH",
    actions: {
        generateKey: ["P-256", "P-384", "P-521", "K-256"].map((namedCurve) => {
            return {
                name: namedCurve,
                algorithm: {
                    name: "ECDH",
                    namedCurve,
                },
                extractable: false,
                keyUsages: ["deriveKey", "deriveBits"],
            };
        }),
        import: [
            {
                name: "JWK public key P-256",
                format: "jwk",
                data: {
                    crv: "P-256",
                    ext: true,
                    key_ops: ["verify"],
                    kty: "EC",
                    x: "dJ9C3NyXDa3fMeZ477NWdp9W6faytA7A_U1ub-tyRcs",
                    y: "aS0_VVe_SeIm8w5TBWjUEco7us6EJUMPKKJaIh36Lho",
                },
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "JWK public key P-384",
                format: "jwk",
                data: {
                    crv: "P-384",
                    ext: true,
                    key_ops: ["verify"],
                    kty: "EC",
                    x: "eHlLZ4jnt_Drs-qoVxK-SZZvhNhi34jLCgyaEZ9XI6bdlK3y1ettm8K5SnLtDhWO",
                    y: "qbr3pOOViYDQ2wWG-_9pwQ0S8cHV0LP-x9JO5dl-dsFYtbGix9YH7fRNOl8GkP-6",
                },
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "JWK public key P-521",
                format: "jwk",
                data: {
                    crv: "P-521",
                    ext: true,
                    key_ops: ["verify"],
                    kty: "EC",
                    x: "Adqn62IVQX8LIauAXrUtxH05DHlRygKcsP9qWAnd9tfJvpaG7bzIs16WMEUe1V-f4AxbQJceU4xCP8dJppK_fzdC",
                    y: "AEo3s1eExCOvpuBtBWnWlr7TuFhq_fMzqX9eqDHiy8qWl4I_koQtMePodrAc85mVrJAjvsa77Y3Ul3QtIWpXXBqa",
                },
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "SPKI P-256",
                format: "spki",
                data: pvtsutils.Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoZMMqyfA16N6bvloFHmalk/SGMisr3zSXFZdR8F9UkaY7hF13hHiQtwp2YO+1zd7jwYi1Y7SMA9iUrC+ap2OCw=="),
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "SPKI P-384",
                format: "spki",
                data: pvtsutils.Convert.FromBase64("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8Kf5Wv21nksy0LuMlkMZv9sxTVAmzNWt81b6MVlYuzxl9D2/obwoVp86pTe4BM79gWWj8pfLc1XrjaIyMSrV8+05IejRLB3i4c0KTGA6QARGm3/AOm0MbTt6kMQF7drL"),
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "SPKI P-521",
                format: "spki",
                data: pvtsutils.Convert.FromBase64("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB+/g37ii0T5iLHCAaXcYRRoNpT0LhfeAr88OwQY4cUpQm1S9lkR0EVUtyuYrYsMB8FarhAZYsLtOiyhjl/Y5f+lQAZ6veWILhbDcbrSNhTPSp3wamAm8QT3EjPUkJlYjHefuAUBIYS9pl5FWjK1pI9fkYe3bdAemkjP1ccHVzqZU9sjg="),
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "RAW P-256",
                format: "raw",
                data: pvtsutils.Convert.FromBase64("BEehen4AavxgJkx5EPZpBeopzgZuY+1i3cMR9iYdZj+IY7/h98Q/GboC2BKS6lT0hEyt6y1DFFXj8ytuof4zXR4="),
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "RAW P-384",
                format: "raw",
                data: pvtsutils.Convert.FromBase64("BGYoCpP3Qv4o0s2GWg5xFnasdkI8h6K/LeBm4TV+9HCsqnoXFUJDM5SDeZ0rcCAUUuaPJVn5sedPEKEGW80zmLM1rBOG2RzaBq+uhEJkLpibongnzMZNX2LB58wGJ05f2g=="),
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "RAW P-521",
                format: "raw",
                data: pvtsutils.Convert.FromBase64("BABIiZ3f90HQsl4CYHt7Q1WnOIOs+dxeecfQrew/z+73yI/bUrMlmR3mOVARtvg7ZPX7h3lSSqzA1Vv6iv7bPYekcwDKQPeLJkem//H7zY8xtKY+YrYnLUVv6vPE9jyk2vYkj8QPxQRdeIT5bzY2BzTiTcLHDwi2+w2Eonkt7M+zb4G6xw=="),
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "JWK private key P-256",
                format: "jwk",
                data: {
                    crv: "P-256",
                    d: "RIrfLaesGcEeNy7fOoVIkgMiImJOFw1Y44kdrtK_49I",
                    ext: true,
                    key_ops: ["sign"],
                    kty: "EC",
                    x: "wJls5KwIfRDxJEvyAlo3G84qNY0HjvsujyxDSMYAlm4",
                    y: "I61bQbFgnzfDom68P86kRo98fTrV_9HLeqa4gYnGOdw",
                },
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "JWK private key P-384",
                format: "jwk",
                data: {
                    crv: "P-384",
                    d: "4YQRcOD-4LMLEr-qsRhQ1oq8hfPKa66BfGVUv3LUlsf2OU3aFG5FxabG5xFUoAE2",
                    ext: true,
                    key_ops: ["sign"],
                    kty: "EC",
                    x: "XKewC5QCVW9w-SFyZd3z1vlmCqbYYuJmoGRzKtjwkpYQD_RhNAc3ck29d_t0QmaT",
                    y: "6oSrri3ry1_8c2NKM8aiaJcjwd146ITViezQ7-BpsE1-wDH18P1QkbmR3-Ho54We",
                },
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "JWK private key P-521",
                format: "jwk",
                data: {
                    crv: "P-521",
                    d: "AItxxufCXVzwPVePNe9Acy8HfbmYeUVkiEyFXdsYRnHxqgDpwucVnIJ44-ZWRpuWu5Ep5KVV3vY9Hp8nJfksi7z2",
                    ext: true,
                    key_ops: ["sign"],
                    kty: "EC",
                    x: "AJGuTezC-8F-d_0bBpS502OK0z63vo87Dw99a3NUm6gm5pQC1rwu7LcblGqFWOuFBZhsF8I6OFjYvsR-z3u7hhCA",
                    y: "AFQT8BB9hBf7UwwBUV4im8bFJ7_MD0qOZMVetmdbooMjfec1q3wU5cSoy4LvCnWAaFqu5havUxwnAUuPUWGG_InR",
                },
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "PKCS8 P-256",
                format: "pkcs8",
                data: pvtsutils.Convert.FromBase64("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiVEY5OFo3J7g1BnSw/WEWykY/alrhNmpEBLy/7cNnuGhRANCAAQ4SFnMDGYc5kWv7D0gtgUj/Bzbu0B6Bq6XK1vqOo//2m8FS1D4kYKV4KDfFRWehKEtrMBjjkW6OZcM/n0qZ6Uw"),
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "PKCS8 P-384",
                format: "pkcs8",
                data: pvtsutils.Convert.FromBase64("MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCY18ajGPCgLv4aF1UkkohMEaB5MU1MyfkuFQSQVDYHLWFTn8f9czce7aTIDjkCx0OhZANiAAR1fni8TC1N1NdXvx25kJyK3y3rpVVaAmA44Wm9jIFseGmSzm/EgmKOFclSzQdEpSC6jxi3olIJ4iYetjl36Ygfwed/xqrsiV6BUb/ny2mimzk3r0M9H6yvbEVQFd7rEAA="),
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "PKCS8 P-521",
                format: "pkcs8",
                data: pvtsutils.Convert.FromBase64("MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAbHGkGfik5q0l+ZMI70dbpTGWeKy1+c3mG98wHmnpU+d2bArcYDOXcoqg5Ic/pnmtHvxmk+El33u3XogGONKPlouhgYkDgYYABAH16CoJzEx+Oncpeam6ysUG17y9ttNm5Eg8WqD+BJkP9ju3R22I5PVyYYYZ3ICc1IyDGxFCS7leO1N7tqQLaLi8NAEFTkwCy1G6AAK7LbSa1hNC2fUAaC9L8QJNUNJpjgYiXPDmEnaRNT1XXL00Bjo5iMpE2Ddc/Kp6ktTAo2jOMnfmow=="),
                algorithm: {
                    name: "ECDH",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
        ],
        deriveBits: [
            {
                name: "P-256 128",
                key: {
                    privateKey: {
                        format: "pkcs8",
                        data: pvtsutils.Convert.FromBase64("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQA7bkTNYlIYVb9+DavBlJ3b08f0892or3XwfscA3tLGhRANCAARzsy+ZcbrNchF7SrpL0hYnGp6ICX77jXUrpMYkq0BuzfaPFWcu9YZH5ASUzQJGz9eCK3mDXEbLCuiHRw3dwkFs"),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-256",
                        },
                        extractable: true,
                        keyUsages: ["deriveBits"],
                    },
                    publicKey: {
                        format: "spki",
                        data: pvtsutils.Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc7MvmXG6zXIRe0q6S9IWJxqeiAl++411K6TGJKtAbs32jxVnLvWGR+QElM0CRs/Xgit5g1xGywroh0cN3cJBbA=="),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-256",
                        },
                        extractable: true,
                        keyUsages: [],
                    },
                },
                data: pvtsutils.Convert.FromBase64("Jlc1/Zqi/8mH1oQT8+YfCA=="),
                algorithm: {
                    name: "ECDH",
                },
                length: 128,
            },
            {
                name: "P-384 192",
                key: {
                    privateKey: {
                        format: "pkcs8",
                        data: pvtsutils.Convert.FromBase64("MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAFOXcWxQ+YqPdUqc9Iar3ZDf012ZtQAFajBMApKpd2WPQccBmyPzvDZJSWKe3d5jShZANiAAQ4Z43bP7d5fUFIBorLA1pBFTwDLb6XA7J871VUwyu64q8L5qidV7iBZK3P+9m7eMMQWm0drWPvrEszE+4jEsS4HIbBeuduBU+6R46Orv+V6VXU1hAXKSdMFZOCzdbDFlE="),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-384",
                        },
                        extractable: true,
                        keyUsages: ["deriveBits"],
                    },
                    publicKey: {
                        format: "spki",
                        data: pvtsutils.Convert.FromBase64("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOGeN2z+3eX1BSAaKywNaQRU8Ay2+lwOyfO9VVMMruuKvC+aonVe4gWStz/vZu3jDEFptHa1j76xLMxPuIxLEuByGwXrnbgVPukeOjq7/lelV1NYQFyknTBWTgs3WwxZR"),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-384",
                        },
                        extractable: true,
                        keyUsages: [],
                    },
                },
                data: pvtsutils.Convert.FromBase64("2EKT/nmV68wIXFMZiCv4CyOEhWzpwdQ5"),
                algorithm: {
                    name: "ECDH",
                },
                length: 192,
            },
            {
                name: "P-521 256",
                key: {
                    privateKey: {
                        format: "pkcs8",
                        data: pvtsutils.Convert.FromBase64("MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6PyCXpJ4TWPpwlGAmayLz5ecYHT+1ilxD64HytpTaViUS72sEzG1JMApD31+STX0zeVcARfG+yh71dXLCTlqqHGhgYkDgYYABADgIblBbth8vnOZt/HLU9VdUJHmenwRRADVZWL+P5IeCDQs6B87API41R3+91xFDHnjst9VKksYl/NJIIfl6b9cmABO6z80mTz3+0klquIpSQLidK2aFaFbqiGnMdCO+AZfwxu2qBx+1f5MwbHXUW5HXsfmEvzBUC9xCQKLpQ8oZYBrSg=="),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-521",
                        },
                        extractable: true,
                        keyUsages: ["deriveBits"],
                    },
                    publicKey: {
                        format: "spki",
                        data: pvtsutils.Convert.FromBase64("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA4CG5QW7YfL5zmbfxy1PVXVCR5np8EUQA1WVi/j+SHgg0LOgfOwDyONUd/vdcRQx547LfVSpLGJfzSSCH5em/XJgATus/NJk89/tJJariKUkC4nStmhWhW6ohpzHQjvgGX8MbtqgcftX+TMGx11FuR17H5hL8wVAvcQkCi6UPKGWAa0o="),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-521",
                        },
                        extractable: true,
                        keyUsages: [],
                    },
                },
                data: pvtsutils.Convert.FromBase64("AS2ene28pmWYdJwW6dyTXUe1eq1p2i8QEIo/rXSiJRo="),
                algorithm: {
                    name: "ECDH",
                },
                length: 256,
            },
            {
                name: "K-256 128",
                key: {
                    privateKey: {
                        format: "pkcs8",
                        data: pvtsutils.Convert.FromBase64("MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQghgLhhrz/EYuB0G08/UoM5nV9jS7Pl/rtIcXeJkc2b3uhRANCAARgMfEiAPcF7pmEuLRGRRFXEKSwcJwqURKK/Pqo8MaqU0cl7eNQmLJ7mFpBtTDY8hr9xxJeIP9sI/u83A1F5ag7"),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "K-256",
                        },
                        extractable: true,
                        keyUsages: ["deriveBits"],
                    },
                    publicKey: {
                        format: "spki",
                        data: pvtsutils.Convert.FromBase64("MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEYDHxIgD3Be6ZhLi0RkURVxCksHCcKlESivz6qPDGqlNHJe3jUJiye5haQbUw2PIa/ccSXiD/bCP7vNwNReWoOw=="),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "K-256",
                        },
                        extractable: true,
                        keyUsages: [],
                    },
                },
                data: pvtsutils.Convert.FromBase64("3+2JX3D4/veBGJXnvU+aTg=="),
                algorithm: {
                    name: "ECDH",
                },
                length: 128,
            },
        ],
        deriveKey: [
            {
                name: "P-256 128",
                key: {
                    privateKey: {
                        format: "pkcs8",
                        data: pvtsutils.Convert.FromBase64("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQA7bkTNYlIYVb9+DavBlJ3b08f0892or3XwfscA3tLGhRANCAARzsy+ZcbrNchF7SrpL0hYnGp6ICX77jXUrpMYkq0BuzfaPFWcu9YZH5ASUzQJGz9eCK3mDXEbLCuiHRw3dwkFs"),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-256",
                        },
                        extractable: true,
                        keyUsages: ["deriveKey"],
                    },
                    publicKey: {
                        format: "spki",
                        data: pvtsutils.Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc7MvmXG6zXIRe0q6S9IWJxqeiAl++411K6TGJKtAbs32jxVnLvWGR+QElM0CRs/Xgit5g1xGywroh0cN3cJBbA=="),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-256",
                        },
                        extractable: true,
                        keyUsages: [],
                    },
                },
                algorithm: {
                    name: "ECDH",
                },
                derivedKeyType: {
                    name: "AES-CBC",
                    length: 128,
                },
                keyUsages: ["encrypt", "decrypt"],
                format: "raw",
                keyData: pvtsutils.Convert.FromBase64("Jlc1/Zqi/8mH1oQT8+YfCA=="),
            },
            {
                name: "P-384 192",
                key: {
                    privateKey: {
                        format: "pkcs8",
                        data: pvtsutils.Convert.FromBase64("MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAFOXcWxQ+YqPdUqc9Iar3ZDf012ZtQAFajBMApKpd2WPQccBmyPzvDZJSWKe3d5jShZANiAAQ4Z43bP7d5fUFIBorLA1pBFTwDLb6XA7J871VUwyu64q8L5qidV7iBZK3P+9m7eMMQWm0drWPvrEszE+4jEsS4HIbBeuduBU+6R46Orv+V6VXU1hAXKSdMFZOCzdbDFlE="),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-384",
                        },
                        extractable: true,
                        keyUsages: ["deriveKey"],
                    },
                    publicKey: {
                        format: "spki",
                        data: pvtsutils.Convert.FromBase64("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOGeN2z+3eX1BSAaKywNaQRU8Ay2+lwOyfO9VVMMruuKvC+aonVe4gWStz/vZu3jDEFptHa1j76xLMxPuIxLEuByGwXrnbgVPukeOjq7/lelV1NYQFyknTBWTgs3WwxZR"),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-384",
                        },
                        extractable: true,
                        keyUsages: [],
                    },
                },
                algorithm: {
                    name: "ECDH",
                },
                derivedKeyType: {
                    name: "AES-GCM",
                    length: 192,
                },
                keyUsages: ["encrypt", "decrypt"],
                format: "raw",
                keyData: pvtsutils.Convert.FromBase64("2EKT/nmV68wIXFMZiCv4CyOEhWzpwdQ5"),
            },
            {
                name: "P-521 256",
                key: {
                    privateKey: {
                        format: "pkcs8",
                        data: pvtsutils.Convert.FromBase64("MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6PyCXpJ4TWPpwlGAmayLz5ecYHT+1ilxD64HytpTaViUS72sEzG1JMApD31+STX0zeVcARfG+yh71dXLCTlqqHGhgYkDgYYABADgIblBbth8vnOZt/HLU9VdUJHmenwRRADVZWL+P5IeCDQs6B87API41R3+91xFDHnjst9VKksYl/NJIIfl6b9cmABO6z80mTz3+0klquIpSQLidK2aFaFbqiGnMdCO+AZfwxu2qBx+1f5MwbHXUW5HXsfmEvzBUC9xCQKLpQ8oZYBrSg=="),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-521",
                        },
                        extractable: true,
                        keyUsages: ["deriveKey"],
                    },
                    publicKey: {
                        format: "spki",
                        data: pvtsutils.Convert.FromBase64("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA4CG5QW7YfL5zmbfxy1PVXVCR5np8EUQA1WVi/j+SHgg0LOgfOwDyONUd/vdcRQx547LfVSpLGJfzSSCH5em/XJgATus/NJk89/tJJariKUkC4nStmhWhW6ohpzHQjvgGX8MbtqgcftX+TMGx11FuR17H5hL8wVAvcQkCi6UPKGWAa0o="),
                        algorithm: {
                            name: "ECDH",
                            namedCurve: "P-521",
                        },
                        extractable: true,
                        keyUsages: [],
                    },
                },
                algorithm: {
                    name: "ECDH",
                },
                derivedKeyType: {
                    name: "AES-CTR",
                    length: 256,
                },
                keyUsages: ["encrypt", "decrypt"],
                format: "raw",
                keyData: pvtsutils.Convert.FromBase64("AS2ene28pmWYdJwW6dyTXUe1eq1p2i8QEIo/rXSiJRo="),
            },
        ],
    },
};

const ECDSA = {
    name: "ECDSA",
    actions: {
        generateKey: ["P-256", "P-384", "P-521", "K-256"].map((namedCurve) => {
            return {
                name: namedCurve,
                algorithm: {
                    name: "ECDSA",
                    namedCurve,
                },
                extractable: false,
                keyUsages: ["sign", "verify"],
            };
        }),
        import: [
            {
                name: "JWK public key P-256",
                format: "jwk",
                data: {
                    crv: "P-256",
                    ext: true,
                    key_ops: ["verify"],
                    kty: "EC",
                    x: "dJ9C3NyXDa3fMeZ477NWdp9W6faytA7A_U1ub-tyRcs",
                    y: "aS0_VVe_SeIm8w5TBWjUEco7us6EJUMPKKJaIh36Lho",
                },
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "JWK public key P-384",
                format: "jwk",
                data: {
                    crv: "P-384",
                    ext: true,
                    key_ops: ["verify"],
                    kty: "EC",
                    x: "eHlLZ4jnt_Drs-qoVxK-SZZvhNhi34jLCgyaEZ9XI6bdlK3y1ettm8K5SnLtDhWO",
                    y: "qbr3pOOViYDQ2wWG-_9pwQ0S8cHV0LP-x9JO5dl-dsFYtbGix9YH7fRNOl8GkP-6",
                },
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "JWK public key P-521",
                format: "jwk",
                data: {
                    crv: "P-521",
                    ext: true,
                    key_ops: ["verify"],
                    kty: "EC",
                    x: "Adqn62IVQX8LIauAXrUtxH05DHlRygKcsP9qWAnd9tfJvpaG7bzIs16WMEUe1V-f4AxbQJceU4xCP8dJppK_fzdC",
                    y: "AEo3s1eExCOvpuBtBWnWlr7TuFhq_fMzqX9eqDHiy8qWl4I_koQtMePodrAc85mVrJAjvsa77Y3Ul3QtIWpXXBqa",
                },
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "SPKI P-256",
                format: "spki",
                data: pvtsutils.Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoZMMqyfA16N6bvloFHmalk/SGMisr3zSXFZdR8F9UkaY7hF13hHiQtwp2YO+1zd7jwYi1Y7SMA9iUrC+ap2OCw=="),
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "SPKI P-384",
                format: "spki",
                data: pvtsutils.Convert.FromBase64("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8Kf5Wv21nksy0LuMlkMZv9sxTVAmzNWt81b6MVlYuzxl9D2/obwoVp86pTe4BM79gWWj8pfLc1XrjaIyMSrV8+05IejRLB3i4c0KTGA6QARGm3/AOm0MbTt6kMQF7drL"),
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "SPKI P-521",
                format: "spki",
                data: pvtsutils.Convert.FromBase64("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB+/g37ii0T5iLHCAaXcYRRoNpT0LhfeAr88OwQY4cUpQm1S9lkR0EVUtyuYrYsMB8FarhAZYsLtOiyhjl/Y5f+lQAZ6veWILhbDcbrSNhTPSp3wamAm8QT3EjPUkJlYjHefuAUBIYS9pl5FWjK1pI9fkYe3bdAemkjP1ccHVzqZU9sjg="),
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "RAW P-256",
                format: "raw",
                data: pvtsutils.Convert.FromBase64("BEehen4AavxgJkx5EPZpBeopzgZuY+1i3cMR9iYdZj+IY7/h98Q/GboC2BKS6lT0hEyt6y1DFFXj8ytuof4zXR4="),
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "RAW P-384",
                format: "raw",
                data: pvtsutils.Convert.FromBase64("BGYoCpP3Qv4o0s2GWg5xFnasdkI8h6K/LeBm4TV+9HCsqnoXFUJDM5SDeZ0rcCAUUuaPJVn5sedPEKEGW80zmLM1rBOG2RzaBq+uhEJkLpibongnzMZNX2LB58wGJ05f2g=="),
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "RAW P-521",
                format: "raw",
                data: pvtsutils.Convert.FromBase64("BABIiZ3f90HQsl4CYHt7Q1WnOIOs+dxeecfQrew/z+73yI/bUrMlmR3mOVARtvg7ZPX7h3lSSqzA1Vv6iv7bPYekcwDKQPeLJkem//H7zY8xtKY+YrYnLUVv6vPE9jyk2vYkj8QPxQRdeIT5bzY2BzTiTcLHDwi2+w2Eonkt7M+zb4G6xw=="),
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["verify"],
            },
            {
                name: "JWK private key P-256",
                format: "jwk",
                data: {
                    crv: "P-256",
                    d: "RIrfLaesGcEeNy7fOoVIkgMiImJOFw1Y44kdrtK_49I",
                    ext: true,
                    key_ops: ["sign"],
                    kty: "EC",
                    x: "wJls5KwIfRDxJEvyAlo3G84qNY0HjvsujyxDSMYAlm4",
                    y: "I61bQbFgnzfDom68P86kRo98fTrV_9HLeqa4gYnGOdw",
                },
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "JWK private key P-384",
                format: "jwk",
                data: {
                    crv: "P-384",
                    d: "4YQRcOD-4LMLEr-qsRhQ1oq8hfPKa66BfGVUv3LUlsf2OU3aFG5FxabG5xFUoAE2",
                    ext: true,
                    key_ops: ["sign"],
                    kty: "EC",
                    x: "XKewC5QCVW9w-SFyZd3z1vlmCqbYYuJmoGRzKtjwkpYQD_RhNAc3ck29d_t0QmaT",
                    y: "6oSrri3ry1_8c2NKM8aiaJcjwd146ITViezQ7-BpsE1-wDH18P1QkbmR3-Ho54We",
                },
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "JWK private key P-521",
                format: "jwk",
                data: {
                    crv: "P-521",
                    d: "AItxxufCXVzwPVePNe9Acy8HfbmYeUVkiEyFXdsYRnHxqgDpwucVnIJ44-ZWRpuWu5Ep5KVV3vY9Hp8nJfksi7z2",
                    ext: true,
                    key_ops: ["sign"],
                    kty: "EC",
                    x: "AJGuTezC-8F-d_0bBpS502OK0z63vo87Dw99a3NUm6gm5pQC1rwu7LcblGqFWOuFBZhsF8I6OFjYvsR-z3u7hhCA",
                    y: "AFQT8BB9hBf7UwwBUV4im8bFJ7_MD0qOZMVetmdbooMjfec1q3wU5cSoy4LvCnWAaFqu5havUxwnAUuPUWGG_InR",
                },
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "PKCS8 P-256",
                format: "pkcs8",
                data: pvtsutils.Convert.FromBase64("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiVEY5OFo3J7g1BnSw/WEWykY/alrhNmpEBLy/7cNnuGhRANCAAQ4SFnMDGYc5kWv7D0gtgUj/Bzbu0B6Bq6XK1vqOo//2m8FS1D4kYKV4KDfFRWehKEtrMBjjkW6OZcM/n0qZ6Uw"),
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "PKCS8 P-384",
                format: "pkcs8",
                data: pvtsutils.Convert.FromBase64("MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCY18ajGPCgLv4aF1UkkohMEaB5MU1MyfkuFQSQVDYHLWFTn8f9czce7aTIDjkCx0OhZANiAAR1fni8TC1N1NdXvx25kJyK3y3rpVVaAmA44Wm9jIFseGmSzm/EgmKOFclSzQdEpSC6jxi3olIJ4iYetjl36Ygfwed/xqrsiV6BUb/ny2mimzk3r0M9H6yvbEVQFd7rEAA="),
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-384",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
            {
                name: "PKCS8 P-521",
                format: "pkcs8",
                data: pvtsutils.Convert.FromBase64("MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAbHGkGfik5q0l+ZMI70dbpTGWeKy1+c3mG98wHmnpU+d2bArcYDOXcoqg5Ic/pnmtHvxmk+El33u3XogGONKPlouhgYkDgYYABAH16CoJzEx+Oncpeam6ysUG17y9ttNm5Eg8WqD+BJkP9ju3R22I5PVyYYYZ3ICc1IyDGxFCS7leO1N7tqQLaLi8NAEFTkwCy1G6AAK7LbSa1hNC2fUAaC9L8QJNUNJpjgYiXPDmEnaRNT1XXL00Bjo5iMpE2Ddc/Kp6ktTAo2jOMnfmow=="),
                algorithm: {
                    name: "ECDSA",
                    namedCurve: "P-521",
                },
                extractable: true,
                keyUsages: ["sign"],
            },
        ],
        sign: [
            {
                key: {
                    privateKey: {
                        format: "pkcs8",
                        data: pvtsutils.Convert.FromBase64("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsY5TBHM+9mLXGpFaPmrigl6+jl0XWzazxu1lbwb5KRahRANCAATqDP2L/xxSOlckG+j6oPHfzBE4WpmjA/YE9sP2rXpXW1qe9I/GJ7wjlOTXpqHUxQeBbps8jSvV+A7DzQqzjOst"),
                        algorithm: {
                            name: "ECDSA",
                            namedCurve: "P-256",
                        },
                        extractable: true,
                        keyUsages: ["sign"],
                    },
                    publicKey: {
                        format: "spki",
                        data: pvtsutils.Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6gz9i/8cUjpXJBvo+qDx38wROFqZowP2BPbD9q16V1tanvSPxie8I5Tk16ah1MUHgW6bPI0r1fgOw80Ks4zrLQ=="),
                        algorithm: {
                            name: "ECDSA",
                            namedCurve: "P-256",
                        },
                        extractable: true,
                        keyUsages: ["verify"],
                    },
                },
                data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
                signature: pvtsutils.Convert.FromBase64("gsTh0IcWfzj3hjjourRgzTIsNa+wcDEDlKnkEA4Jv8ygLF2IDIOXpCD7ocCGo7xlSMGTme78CyrPqWGSz95mZg=="),
                algorithm: {
                    name: "ECDSA",
                    hash: "SHA-256",
                },
            },
            {
                key: {
                    privateKey: {
                        format: "pkcs8",
                        data: pvtsutils.Convert.FromBase64("MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg0h6+W+/4eFVP+i79hrzYeiEJ6UrveFYhuhoXRW+g/LGhRANCAASiJU6MaFN5fshUv6X5rCf/RjLQ0nAXj06gBdo3ruYiKZf8daAcYImniAq81PjF0j6eTwCy4bYbkyfBQtrtCTKR"),
                        algorithm: {
                            name: "ECDSA",
                            namedCurve: "K-256",
                        },
                        extractable: true,
                        keyUsages: ["sign"],
                    },
                    publicKey: {
                        format: "spki",
                        data: pvtsutils.Convert.FromBase64("MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEoiVOjGhTeX7IVL+l+awn/0Yy0NJwF49OoAXaN67mIimX/HWgHGCJp4gKvNT4xdI+nk8AsuG2G5MnwULa7QkykQ=="),
                        algorithm: {
                            name: "ECDSA",
                            namedCurve: "K-256",
                        },
                        extractable: true,
                        keyUsages: ["verify"],
                    },
                },
                data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
                signature: pvtsutils.Convert.FromBase64("lqUTZHqf9v9KcOCw5r5wR1sCt9RPA0ONVW6vqejpoALehd6vtAb+ybVrDEtyUDpBFw9UIRIW6GnXRrAz4KaO4Q=="),
                algorithm: {
                    name: "ECDSA",
                    hash: "SHA-256",
                },
            },
        ],
    },
};

const HKDF = {
    name: "HKDF",
    actions: {
        import: [
            {
                name: "raw",
                format: "raw",
                data: Buffer.from("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "hex"),
                algorithm: {
                    name: "HKDF",
                },
                extractable: false,
                keyUsages: ["deriveBits", "deriveKey"],
            },
        ],
        deriveBits: [
            {
                key: {
                    format: "raw",
                    data: Buffer.from("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "hex"),
                    algorithm: {
                        name: "HKDF",
                    },
                    extractable: false,
                    keyUsages: ["deriveBits"],
                },
                algorithm: {
                    name: "HKDF",
                    hash: { name: "SHA-256" },
                    salt: Buffer.from("000102030405060708090a0b0c", "hex"),
                    info: Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex"),
                },
                data: Buffer.from("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "hex"),
                length: 42 * 8,
            },
            {
                key: {
                    format: "raw",
                    data: Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", "hex"),
                    algorithm: {
                        name: "HKDF",
                    },
                    extractable: false,
                    keyUsages: ["deriveBits"],
                },
                algorithm: {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: Buffer.from("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "hex"),
                    info: Buffer.from("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex"),
                },
                data: Buffer.from("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87", "hex"),
                length: 82 * 8,
            },
            {
                key: {
                    format: "raw",
                    data: Buffer.from("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "hex"),
                    algorithm: {
                        name: "HKDF",
                    },
                    extractable: false,
                    keyUsages: ["deriveBits"],
                },
                algorithm: {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: Buffer.from([]),
                    info: Buffer.from([]),
                },
                data: Buffer.from("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", "hex"),
                length: 42 * 8,
            },
        ],
    }
};

const PBKDF2 = {
    name: "PBKDF2",
    actions: {
        deriveBits: [
            {
                key: {
                    format: "raw",
                    data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
                    algorithm: {
                        name: "PBKDF2",
                    },
                    extractable: false,
                    keyUsages: ["deriveBits"],
                },
                algorithm: {
                    name: "PBKDF2",
                    salt: new Uint8Array([1, 2, 3, 4]),
                    hash: "SHA-256",
                    iterations: 1000,
                },
                data: pvtsutils.Convert.FromBase64("3GK58/4RT+UPLooz5HT1MQ=="),
                length: 128,
            },
        ],
        deriveKey: [
            {
                key: {
                    format: "raw",
                    data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
                    algorithm: {
                        name: "PBKDF2",
                    },
                    extractable: false,
                    keyUsages: ["deriveKey"],
                },
                algorithm: {
                    name: "PBKDF2",
                    salt: new Uint8Array([1, 2, 3, 4]),
                    hash: "SHA-256",
                    iterations: 1000,
                },
                derivedKeyType: {
                    name: "AES-CBC",
                    length: 128,
                },
                keyUsages: ["encrypt"],
                format: "raw",
                keyData: pvtsutils.Convert.FromBase64("3GK58/4RT+UPLooz5HT1MQ=="),
            },
        ],
    },
};

const HMAC = {
    name: "HMAC",
    actions: {
        generateKey: [
            {
                name: "default length",
                algorithm: {
                    name: "HMAC",
                    hash: "SHA-256",
                },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
            ...["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
                return {
                    name: hash,
                    algorithm: {
                        name: "HMAC",
                        hash,
                        length: 128,
                    },
                    extractable: true,
                    keyUsages: ["sign", "verify"],
                };
            }),
            {
                name: "length:160",
                algorithm: {
                    name: "HMAC",
                    hash: "SHA-256",
                    length: 160,
                },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
        ],
        sign: [
            {
                name: "HMAC-SHA256 with length param which is less than hash size",
                key: {
                    format: "raw",
                    data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]),
                    algorithm: {
                        name: "HMAC",
                        hash: "SHA-256",
                        length: 128,
                    },
                    extractable: false,
                    keyUsages: ["sign", "verify"],
                },
                algorithm: { name: "HMAC" },
                data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
                signature: pvtsutils.Convert.FromBase64("9yMF9ReX1EhdBWTRjSR+AC21NA05H9W8vx0HZGVmgNc="),
            },
            {
                name: "HMAC-SHA256 without length param",
                key: {
                    format: "raw",
                    data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]),
                    algorithm: {
                        name: "HMAC",
                        hash: "SHA-256",
                    },
                    extractable: false,
                    keyUsages: ["sign", "verify"],
                },
                algorithm: { name: "HMAC" },
                data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
                signature: pvtsutils.Convert.FromHex("ad05febab44cd369e27433bbf00e63e6271f6a350614bec453f5d0efd6503a31"),
            },
        ],
        import: [
            {
                name: "JWK SHA-1",
                format: "jwk",
                data: {
                    alg: "HS1",
                    ext: true,
                    k: "AQIDBAUGBwgJAAECAwQFBg",
                    key_ops: ["sign", "verify"],
                    kty: "oct",
                },
                algorithm: {
                    name: "HMAC",
                    hash: "SHA-1",
                    length: 128,
                },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
            {
                name: "JWK SHA-256",
                format: "jwk",
                data: {
                    alg: "HS256",
                    ext: true,
                    k: "AQIDBAUGBwgJAAECAwQFBg",
                    key_ops: ["sign", "verify"],
                    kty: "oct",
                },
                algorithm: {
                    name: "HMAC",
                    hash: "SHA-256",
                },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
            {
                name: "JWK SHA-384",
                format: "jwk",
                data: {
                    alg: "HS384",
                    ext: true,
                    k: "AQIDBAUGBwgJAAECAwQFBg",
                    key_ops: ["sign", "verify"],
                    kty: "oct",
                },
                algorithm: {
                    name: "HMAC",
                    hash: "SHA-384",
                },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
            {
                name: "JWK SHA-512",
                format: "jwk",
                data: {
                    alg: "HS512",
                    ext: true,
                    k: "AQIDBAUGBwgJAAECAwQFBg",
                    key_ops: ["sign", "verify"],
                    kty: "oct",
                },
                algorithm: {
                    name: "HMAC",
                    hash: "SHA-512",
                },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
            {
                name: "raw 128",
                format: "raw",
                data: pvtsutils.Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg"),
                algorithm: {
                    name: "HMAC",
                    hash: "SHA-512",
                },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
            {
                name: "raw 160",
                format: "raw",
                data: new Uint8Array(20),
                algorithm: {
                    name: "HMAC",
                    hash: "SHA-512",
                },
                extractable: true,
                keyUsages: ["sign", "verify"],
            },
        ],
    },
};

const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
const SHA = {
    name: "SHA",
    actions: {
        digest: [
            {
                name: "SHA-1",
                algorithm: "SHA-1",
                data,
                hash: pvtsutils.Convert.FromBase64("6JrVqWMcPv3e1+Psznm00P7c4b8="),
            },
            {
                name: "SHA-256",
                algorithm: "SHA-256",
                data,
                hash: pvtsutils.Convert.FromBase64("monGjExeKLjEpVZ2c9Ri//UV20YRb5kAYk0JxHT1k/s="),
            },
            {
                name: "SHA-384",
                algorithm: "SHA-384",
                data,
                hash: pvtsutils.Convert.FromBase64("E9WqubQC9JnxffIniWwf0soI91o5z0Kbvk+s/32Fi3z28kAh+Fcne7Hgy1nnW4rR"),
            },
            {
                name: "SHA-512",
                algorithm: "SHA-512",
                data,
                hash: pvtsutils.Convert.FromBase64("OtPzaXlFDU9TNmJE7PEBD0+RIdaIgoX/FBBP1a3thdSKoXG/HjOhEmAvkrenCIsph4kBL7h7kFYyEkGhn7dOCw=="),
            },
        ],
    },
};



var Vectors = /*#__PURE__*/Object.freeze({
  __proto__: null,
  AES128CBC: AES128CBC,
  AES192CBC: AES192CBC,
  AES256CBC: AES256CBC,
  AES128CTR: AES128CTR,
  AES192CTR: AES192CTR,
  AES256CTR: AES256CTR,
  AES128CMAC: AES128CMAC,
  AES192CMAC: AES192CMAC,
  AES128GCM: AES128GCM,
  AES192GCM: AES192GCM,
  AES256GCM: AES256GCM,
  AES128KW: AES128KW,
  AES192KW: AES192KW,
  AES256KW: AES256KW,
  AES128ECB: AES128ECB,
  AES192ECB: AES192ECB,
  AES256ECB: AES256ECB,
  RSAPSS: RSAPSS,
  RSAOAEP: RSAOAEP,
  RSAESPKCS1: RSAESPKCS1,
  RSASSAPKCS1: RSASSAPKCS1,
  DESCBC: DESCBC,
  DESEDE3CBC: DESEDE3CBC,
  ECDH: ECDH,
  ECDSA: ECDSA,
  HKDF: HKDF,
  PBKDF2: PBKDF2,
  HMAC: HMAC,
  SHA: SHA
});

class WebcryptoTest {
    static add(crypto, param) {
        testCrypto(crypto, param);
    }
    static check(crypto, vectors) {
        if (Array.isArray(vectors)) {
            vectors.forEach((element) => {
                testCrypto(crypto, element);
            });
        }
        else {
            for (const key in Vectors) {
                if (!(vectors === null || vectors === void 0 ? void 0 : vectors[key])) {
                    testCrypto(crypto, Vectors[key]);
                }
            }
        }
    }
}

exports.WebcryptoTest = WebcryptoTest;
exports.vectors = Vectors;
