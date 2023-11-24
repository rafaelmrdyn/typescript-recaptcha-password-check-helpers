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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoHelper = void 0;
const node_crypto_1 = require("node:crypto");
const bit_prefix_1 = require("./bit_prefix");
/**
 * Set of functions to perform cryptographic operations for password check.
 */
class CryptoHelper {
    constructor() { }
    /**
     * Produces username hash. `canonicalizedUsername` is pre-canonicalized
     * using {@see #canonicalizeUsername}.
     *
     * *Note*: the username hash is not safe against offline attacks, but that's
     * acceptable since the client only exposes a limited number of bits about it.
     * The server itself never returns a username hash.
     */
    static hashUsername(canonicalizedUsername) {
        const usernameBytes = new TextEncoder().encode(canonicalizedUsername);
        const hashInput = new Uint8Array(usernameBytes.length + CryptoHelper.USERNAME_HASH_CONSTANT_SALT.length);
        hashInput.set(usernameBytes);
        hashInput.set(CryptoHelper.USERNAME_HASH_CONSTANT_SALT, usernameBytes.length);
        return new Uint8Array((0, node_crypto_1.createHash)('sha256').update(hashInput).digest());
    }
    /**
     * Canonicalizes a username by lower-casing ASCII characters, stripping a
     * mail-address host in case the username is a mail address, and stripping
     * dots.
     */
    static canonicalizeUsername(username) {
        if (CryptoHelper.isEmail(username)) {
            const atIndex = username.lastIndexOf('@');
            username = username.substring(0, atIndex);
        }
        return username.toLowerCase().replace('.', '');
    }
    /**
     * Produces a username-password pair hash. `canonicalizedUsername` is
     * pre-canonicalized using {@see #canonicalizeUsername}.
     *
     * *Note*: this hash is relatively safe against offline attacks. However, a
     * second layer of protection comes from the fact that these hashes are never
     * returned in cleartext to the client, but rather only encrypted with a
     * commutative cipher. Hence, the slowness of this hashing algorithm is not as
     * critical.
     *
     * *Performance*: this is a very resource-intensive operation, since the
     * hashing algorithm used is very time and memory complex. If multiple hashes
     * are done, this should be executed outside of the request thread.
     */
    static hashUsernamePasswordPair(username, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const usernameBytes = new TextEncoder().encode(username);
            const passwordBytes = new TextEncoder().encode(password);
            const hashInput = new Uint8Array(usernameBytes.length + passwordBytes.length);
            hashInput.set(usernameBytes);
            hashInput.set(passwordBytes, usernameBytes.length);
            const saltInput = new Uint8Array(usernameBytes.length + CryptoHelper.PASSWORD_HASH_CONSTANT_SALT.length);
            saltInput.set(usernameBytes);
            saltInput.set(CryptoHelper.PASSWORD_HASH_CONSTANT_SALT, usernameBytes.length);
            return yield CryptoHelper.scrypt(hashInput, saltInput, CryptoHelper.SCRYPT_PASSWORD_HASH_KEY_LENGTH, {
                cost: CryptoHelper.SCRYPT_PASSWORD_HASH_CPU_MEM_COST,
                blockSize: CryptoHelper.SCRYPT_PASSWORD_HASH_BLOCK_SIZE,
                parallelization: CryptoHelper.SCRYPT_PASSWORD_HASH_PARALLELIZATION
            });
        });
    }
    /**
     * Returns a byte array containing the prefix of the hashed {@code
     * canonicalizedUsername} with the given length.
     */
    static bucketizeUsername(canonicalizedUsername, allowedUsernameHashPrefixLength) {
        return bit_prefix_1.BitPrefix
            .of(CryptoHelper.hashUsername(canonicalizedUsername), allowedUsernameHashPrefixLength)
            .prefix;
    }
    /**
     * Converts the callback-style `crypto.scrypt` into a `Promise`.
     */
    static scrypt(password, salt, keyLength, options) {
        return new Promise((resolve, reject) => {
            (0, node_crypto_1.scrypt)(password, salt, keyLength, options, (err, data) => {
                if (err !== null) {
                    reject(err);
                }
                else {
                    resolve(data);
                }
            });
        });
    }
    static isEmail(text) {
        return text.indexOf('@') !== -1;
    }
}
exports.CryptoHelper = CryptoHelper;
// Constant salt added to the password hash on top of username. This adds a
// tiny bit of security to the hashes - requiring and attacker to first create
// a rainbow table for this salt.
CryptoHelper.PASSWORD_HASH_CONSTANT_SALT = Uint8Array.of(0x30, 0x76, 0x2A, 0xD2, 0x3F, 0x7B, 0xA1, 0x9B, 0xF8, 0xE3, 0x42, 0xFC, 0xA1, 0xA7, 0x8D, 0x06, 0xE6, 0x6B, 0xE4, 0xDB, 0xB8, 0x4F, 0x81, 0x53, 0xC5, 0x03, 0xC8, 0xDB, 0xBd, 0xDE, 0xA5, 0x20);
// Constant salt added to the username hash. This adds a tiny bit of security
// to the hashes requiring and attacker to first create a rainbow table for
// this salt.
CryptoHelper.USERNAME_HASH_CONSTANT_SALT = Uint8Array.of(0xC4, 0x94, 0xA3, 0x95, 0xF8, 0xC0, 0xE2, 0x3E, 0xA9, 0x23, 0x04, 0x78, 0x70, 0x2C, 0x72, 0x18, 0x56, 0x54, 0x99, 0xB3, 0xE9, 0x21, 0x18, 0x6C, 0x21, 0x1A, 0x01, 0x22, 0x3C, 0x45, 0x4A, 0xFA);
CryptoHelper.SCRYPT_PASSWORD_HASH_CPU_MEM_COST = Math.pow(2, 12);
CryptoHelper.SCRYPT_PASSWORD_HASH_BLOCK_SIZE = 8;
CryptoHelper.SCRYPT_PASSWORD_HASH_PARALLELIZATION = 1;
CryptoHelper.SCRYPT_PASSWORD_HASH_KEY_LENGTH = 32;
