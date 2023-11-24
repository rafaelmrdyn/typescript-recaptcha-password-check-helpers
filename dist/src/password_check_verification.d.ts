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
import { HashType } from './emscripten/ec_commutative_cipher';
import { EcCommutativeCipherImpl } from './emscripten/ec_commutative_cipher_impl';
import { PasswordCheckResult } from './password_check_result';
/**
 * PasswordCheckVerification
 */
export declare class PasswordCheckVerification {
    private readonly ecCipher;
    private readonly username;
    private readonly encryptedUserCredentialsHash;
    private readonly lookupHashPrefix;
    static readonly CURVE_ID = 415;
    static readonly HASH_TYPE = HashType.SHA256;
    static readonly USERNAME_HASH_PREFIX_LENGTH = 26;
    static readonly crypto: Promise<EcCommutativeCipherImpl>;
    /**
     * Private constructor. Use PasswordCheckVerification.create to build a new
     * instance.
     */
    private constructor();
    /**
     * Creates a new PasswordCheckVerification instance. The instance should not
     * be reused to avoid using the same cipher for more than one password leak
     * check.
     */
    static create(username: string, password: string): Promise<PasswordCheckVerification>;
    /**
     * Checks whether or not a leak was found for this password check
     */
    verify(reEncryptedUserCredentialsHash: Uint8Array, encryptedLeakMatchPrefixList: Uint8Array[]): PasswordCheckResult;
    getUsername(): string;
    getEncryptedUserCredentialsHash(): Uint8Array;
    getLookupHashPrefix(): Uint8Array;
    /**
     * Creates a new EcCommutativeCipher to be used for this password check
     * verification.
     */
    private static initEcCipher;
    /**
     * Determines if the given prefix matches with the encrypted credentials
     * hash.
     */
    private isPrefix;
}
