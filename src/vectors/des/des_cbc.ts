import { ITestParams } from "../../types";

export const DESCBC: ITestParams = {
  name: "DES-CBC",
  actions: {
    generateKey: [
      {
        algorithm: { name: "DES-CBC", length: 64 } as any,
        extractable: false,
        keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
      },
    ],
    encrypt: [
      {
        algorithm: {
          name: "DES-CBC",
          iv: Buffer.from("12345678"),
        } as any,
        data: Buffer.from("test message"),
        encData: Buffer.from("3af3f901ff01fe0102dfbbf37d9bdb94", "hex"),
        key: {
          format: "raw" as KeyFormat,
          algorithm: { name: "DES-CBC" },
          extractable: true,
          keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
          data: Buffer.from("12345678"),
        },
      },
    ],
    import: [
      {
        name: "raw",
        format: "raw" as KeyFormat,
        data: Buffer.from("12345678"),
        algorithm: "DES-CBC",
        extractable: true,
        keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
      },
      {
        name: "jwk",
        format: "jwk" as KeyFormat,
        data: {
          kty: "oct",
          alg: "DES-CBC",
          k: "MTIzNDU2Nzg",
          ext: true,
          key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
        },
        algorithm: "DES-CBC",
        extractable: true,
        keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
      },
    ],
  },
};