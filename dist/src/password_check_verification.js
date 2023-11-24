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
exports.PasswordCheckVerification = void 0;
const ec_commutative_cipher_1 = require("./emscripten/ec_commutative_cipher");
const ec_commutative_cipher_impl_1 = require("./emscripten/ec_commutative_cipher_impl");
const node_crypto_1 = require("node:crypto");
const crypto_helper_1 = require("./utils/crypto_helper");
const password_check_result_1 = require("./password_check_result");
/**
 * PasswordCheckVerification
 */
class PasswordCheckVerification {
    /**
     * Private constructor. Use PasswordCheckVerification.create to build a new
     * instance.
     */
    constructor(ecCipher, username, encryptedUserCredentialsHash, lookupHashPrefix) {
        this.ecCipher = ecCipher;
        this.username = username;
        this.encryptedUserCredentialsHash = encryptedUserCredentialsHash;
        this.lookupHashPrefix = lookupHashPrefix;
    }
    /**
     * Creates a new PasswordCheckVerification instance. The instance should not
     * be reused to avoid using the same cipher for more than one password leak
     * check.
     */
    static create(username, password) {
        return __awaiter(this, void 0, void 0, function* () {
            if (username == null || username.length === 0) {
                throw new Error('Username cannot be null or empty');
            }
            if (password == null || password.length === 0) {
                throw new Error('Password cannot be null or empty');
            }
            const ecCipher = yield PasswordCheckVerification.initEcCipher();
            const canonicalizedUsername = crypto_helper_1.CryptoHelper.canonicalizeUsername(username);
            const hashedUsernamePasswordPair = yield crypto_helper_1.CryptoHelper.hashUsernamePasswordPair(canonicalizedUsername, password);
            const encryptedUserCredentialsHash = ecCipher.encrypt(hashedUsernamePasswordPair);
            const lookupHashPrefix = crypto_helper_1.CryptoHelper.bucketizeUsername(canonicalizedUsername, PasswordCheckVerification.USERNAME_HASH_PREFIX_LENGTH);
            return new PasswordCheckVerification(ecCipher, username, encryptedUserCredentialsHash, lookupHashPrefix);
        });
    }
    /**
     * Checks whether or not a leak was found for this password check
     */
    verify(reEncryptedUserCredentialsHash, encryptedLeakMatchPrefixList) {
        if (reEncryptedUserCredentialsHash == null ||
            reEncryptedUserCredentialsHash.length === 0) {
            throw new Error('reEncryptedLookupHash must be present');
        }
        if (encryptedLeakMatchPrefixList == null) {
            throw new Error('encryptedLeakMatchPrefixList cannot be null');
        }
        const serverEncryptedCredentialsHash = this.ecCipher.decrypt(reEncryptedUserCredentialsHash);
        const reHashedEncryptedCredentialsHash = (0, node_crypto_1.createHash)('sha256').update(serverEncryptedCredentialsHash).digest();
        const credentialsLeaked = encryptedLeakMatchPrefixList.some((prefix) => this.isPrefix(reHashedEncryptedCredentialsHash, prefix));
        return new password_check_result_1.PasswordCheckResult(this, this.username, credentialsLeaked);
    }
    getUsername() {
        return this.username;
    }
    getEncryptedUserCredentialsHash() {
        return this.encryptedUserCredentialsHash;
    }
    getLookupHashPrefix() {
        return this.lookupHashPrefix;
    }
    /**
     * Creates a new EcCommutativeCipher to be used for this password check
     * verification.
     */
    static initEcCipher() {
        return __awaiter(this, void 0, void 0, function* () {
            const crypto = yield PasswordCheckVerification.crypto;
            return ec_commutative_cipher_1.EcCommutativeCipher.create(crypto, PasswordCheckVerification.CURVE_ID, PasswordCheckVerification.HASH_TYPE);
        });
    }
    /**
     * Determines if the given prefix matches with the encrypted credentials
     * hash.
     */
    isPrefix(reHashedEncryptedCredentialsHash, prefix) {
        for (let i = 0; i < prefix.length; i++) {
            if (prefix[i] !== reHashedEncryptedCredentialsHash[i]) {
                return false;
            }
        }
        return true;
    }
}
exports.PasswordCheckVerification = PasswordCheckVerification;
// Use NID_X9_62_prime256v1 (secp256r1) curve
PasswordCheckVerification.CURVE_ID = 415;
// SHA256 is used for compatibility with the server and other libraries.
PasswordCheckVerification.HASH_TYPE = ec_commutative_cipher_1.HashType.SHA256;
PasswordCheckVerification.USERNAME_HASH_PREFIX_LENGTH = 26;
PasswordCheckVerification.crypto = ec_commutative_cipher_impl_1.EcCommutativeCipherImpl.createEcCommutativeCipherImpl();
