# webcrypto-test

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/webcrypto-test/master/LICENSE.md)
[![Node.js CI](https://github.com/PeculiarVentures/webcrypto-test/workflows/Node.js%20CI/badge.svg)](https://github.com/PeculiarVentures/webcrypto-test/actions?query=workflow%3A%22Node.js+CI%22)
[![Coverage Status](https://coveralls.io/repos/github/PeculiarVentures/webcrypto-test/badge.svg?branch=master)](https://coveralls.io/github/PeculiarVentures/webcrypto-test?branch=master)
[![npm version](https://badge.fury.io/js/%40peculiar%2Fwebcrypto-test.svg)](https://badge.fury.io/js/%40peculiar%2Fwebcrypto-test)

This module allows you to test cryptographic modules.

## Table Of Contents

* [Installing](#installing)
* [Using](#using)
  * [Run all tests](#run-all-tests)
  * [Run selected tests](#run-selected-tests)
  * [Disable tests](#disable-tests)
  * [Run custom test](#run-custom-test)

## Installing

```
npm install @peculiar/webcrypto-test
```

## Using

### Run all tests
```js
const { WebcryptoTest } = require("@peculiar/webcrypto-test");
const { Crypto } = require("@peculiar/webcrypto");

WebcryptoTest.check( new Crypto());
```
### Run selected tests
```js
const { WebcryptoTest } = require("@peculiar/webcrypto-test");
const  vectors = require("./vectors");
const { Crypto } = require("@peculiar/webcrypto");

WebcryptoTest.check(new Crypto(), [vectors.ECDSA, vectors.ECDH]);
```
### Disable tests
To exclude vectors, you must set them to true
```js
const { WebcryptoTest } = require("@peculiar/webcrypto-test");
const { Crypto } = require("@peculiar/webcrypto");

WebcryptoTest.check(new Crypto(), {
  ECDSA: true,
  ECDH: true,
});
```
### Run custom test
```js
const { WebcryptoTest } = require("@peculiar/webcrypto-test");
const { Crypto } = require("@peculiar/webcrypto");

const myVector = {
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
    ]
  }
}

WebcryptoTest.add(new Crypto(), myVector);
```