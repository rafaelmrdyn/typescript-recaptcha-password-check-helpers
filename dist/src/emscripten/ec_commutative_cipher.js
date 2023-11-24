"use strict";
/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.EcCommutativeCipher = exports.HashType = void 0;
/**
 * The hash function used by the ECCommutativeCipher in order to hash strings
 * to EC curve points.
 */
var HashType;
(function (HashType) {
    HashType[HashType["SHA256"] = 0] = "SHA256";
    HashType[HashType["SHA384"] = 1] = "SHA384";
    HashType[HashType["SHA512"] = 2] = "SHA512";
    HashType[HashType["SSWU_RO"] = 3] = "SSWU_RO";
})(HashType = exports.HashType || (exports.HashType = {}));
/**
 * EcCommutativeCipher library responsible for encryption and decryption.
 */
class EcCommutativeCipher {
    /**
     * Initializes client.
     */
    constructor(crypto, ecCipher) {
        this.crypto = crypto;
        this.ecCipher = ecCipher;
    }
    static create(crypto, curveId, hashType) {
        const ecCipher = crypto.createWithNewKey(curveId, hashType);
        if (ecCipher <= 0) {
            throw new Error('Failed to create WASM-wrapped EcCommutativeCipher.');
        }
        return new EcCommutativeCipher(crypto, ecCipher);
    }
    static createFromKey(crypto, curveId, hashType, key) {
        const ecCipher = crypto.createFromKey(curveId, hashType, key);
        if (ecCipher <= 0) {
            throw new Error('Failed to create WASM-wrapped EcCommutativeCipher from key.');
        }
        return new EcCommutativeCipher(crypto, ecCipher);
    }
    encrypt(plaintext) {
        return this.crypto.encrypt(this.ecCipher, plaintext);
    }
    decrypt(ciphertext) {
        return this.crypto.decrypt(this.ecCipher, ciphertext);
    }
    reencrypt(ciphertext) {
        return this.crypto.reencrypt(this.ecCipher, ciphertext);
    }
    hashToTheCurve(input) {
        return this.crypto.hashToTheCurve(this.ecCipher, input);
    }
}
exports.EcCommutativeCipher = EcCommutativeCipher;
