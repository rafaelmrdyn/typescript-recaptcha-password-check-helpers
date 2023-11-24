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
 * Class containing all WASM-wrapped functions.
 */
export declare class EcCommutativeCipherImpl {
    private readonly ecCommutativeCipherBinary;
    private readonly createWithNewKeyInternal;
    private readonly createFromKeyInternal;
    private readonly encryptInternal;
    private readonly decryptInternal;
    private readonly reencryptInternal;
    private readonly hashToTheCurveInternal;
    private readonly destroyInternal;
    private readonly mallocInternal;
    private readonly freeInternal;
    private constructor();
    /**
     * Factory function to create crypto implementation. Promise will be resolved
     * once all dependencies are initialized.
     */
    static createEcCommutativeCipherImpl(): Promise<EcCommutativeCipherImpl>;
    createWithNewKey(curveId: number, hashType: number): number;
    createFromKey(curveId: number, hashType: number, key: Uint8Array): number;
    encrypt(ecCipher: number, plaintext: Uint8Array): Uint8Array;
    decrypt(ecCipher: number, ciphertext: Uint8Array): Uint8Array;
    reencrypt(ecCipher: number, ciphertext: Uint8Array): Uint8Array;
    hashToTheCurve(ecCipher: number, input: Uint8Array): Uint8Array;
    destroy(ecCipher: number): void;
}
