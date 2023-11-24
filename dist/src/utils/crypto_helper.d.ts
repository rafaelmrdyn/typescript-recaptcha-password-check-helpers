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
/**
 * Set of functions to perform cryptographic operations for password check.
 */
export declare class CryptoHelper {
    private static readonly PASSWORD_HASH_CONSTANT_SALT;
    private static readonly USERNAME_HASH_CONSTANT_SALT;
    private static readonly SCRYPT_PASSWORD_HASH_CPU_MEM_COST;
    private static readonly SCRYPT_PASSWORD_HASH_BLOCK_SIZE;
    private static readonly SCRYPT_PASSWORD_HASH_PARALLELIZATION;
    private static readonly SCRYPT_PASSWORD_HASH_KEY_LENGTH;
    private constructor();
    /**
     * Produces username hash. `canonicalizedUsername` is pre-canonicalized
     * using {@see #canonicalizeUsername}.
     *
     * *Note*: the username hash is not safe against offline attacks, but that's
     * acceptable since the client only exposes a limited number of bits about it.
     * The server itself never returns a username hash.
     */
    static hashUsername(canonicalizedUsername: string): Uint8Array;
    /**
     * Canonicalizes a username by lower-casing ASCII characters, stripping a
     * mail-address host in case the username is a mail address, and stripping
     * dots.
     */
    static canonicalizeUsername(username: string): string;
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
    static hashUsernamePasswordPair(username: string, password: string): Promise<Uint8Array>;
    /**
     * Returns a byte array containing the prefix of the hashed {@code
     * canonicalizedUsername} with the given length.
     */
    static bucketizeUsername(canonicalizedUsername: string, allowedUsernameHashPrefixLength: number): Uint8Array;
    /**
     * Converts the callback-style `crypto.scrypt` into a `Promise`.
     */
    private static scrypt;
    private static isEmail;
}
