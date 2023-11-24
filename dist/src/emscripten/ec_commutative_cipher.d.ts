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
 * g3-format-clang
 * @fileoverview EcCommutativeCipher library.
 *
 * This library is not thread-safe.
 */
import { EcCommutativeCipherImpl } from './ec_commutative_cipher_impl';
/**
 * The hash function used by the ECCommutativeCipher in order to hash strings
 * to EC curve points.
 */
export declare enum HashType {
    SHA256 = 0,
    SHA384 = 1,
    SHA512 = 2,
    SSWU_RO = 3
}
/**
 * EcCommutativeCipher library responsible for encryption and decryption.
 */
export declare class EcCommutativeCipher {
    private readonly crypto;
    private readonly ecCipher;
    /**
     * Initializes client.
     */
    private constructor();
    static create(crypto: EcCommutativeCipherImpl, curveId: number, hashType: number): EcCommutativeCipher;
    static createFromKey(crypto: EcCommutativeCipherImpl, curveId: number, hashType: number, key: Uint8Array): EcCommutativeCipher;
    encrypt(plaintext: Uint8Array): Uint8Array;
    decrypt(ciphertext: Uint8Array): Uint8Array;
    reencrypt(ciphertext: Uint8Array): Uint8Array;
    hashToTheCurve(input: Uint8Array): Uint8Array;
}
