import { Crypto } from "@peculiar/webcrypto";

import { describe, it } from "vitest";
import { WebcryptoTest, vectors } from "../src";

const crypto = new Crypto();
const platform = { describe, it };

WebcryptoTest.check(crypto, {
  DESCBC: true,
  DESEDE3CBC: true,
}, platform);
WebcryptoTest.check(crypto, [vectors.SHA], platform);
WebcryptoTest.check(crypto, {
  AES128CBC: true,
  AES192CBC: true,
  AES256CBC: true,
  AES128CMAC: true,
  AES192CMAC: true,
  AES128CTR: true,
  AES192CTR: true,
  AES256CTR: true,
  AES128ECB: true,
  AES192ECB: true,
  AES256ECB: true,
  AES128GCM: true,
  AES192GCM: true,
  AES256GCM: true,
  AES128KW: true,
  AES192KW: true,
  AES256KW: true,

  DESCBC: true,
  DESEDE3CBC: true,

  RSAESPKCS1: true,
  RSASSAPKCS1: true,
  RSAOAEP: true,
  RSAPSS: true,

  ECDSA: true,
  ECDH: true,

  HKDF: true,
  HMAC: true,
  PBKDF2: true
}, platform);
WebcryptoTest.add(crypto, vectors.SHA, platform);