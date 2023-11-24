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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EcCommutativeCipherImpl = void 0;
/**
 * g3-format-clang
 * @fileoverview Implementation of EcCommutativeCipher in TypeScript.
 */
const ec_commutative_cipher_wasm_loader_closurized_1 = __importDefault(require("../../third_party/ec_commutative_cipher_wasm_loader-closurized"));
const wasmData = __importStar(require("./ec_commutative_cipher_wasm_wasm_embed"));
// Set max allocated memory to be at most 1 KB.
const MAX_ALLOCATED_BYTES = 1000;
/**
 * Class containing all WASM-wrapped functions.
 */
class EcCommutativeCipherImpl {
    constructor(ecCommutativeCipherBinary) {
        this.ecCommutativeCipherBinary = ecCommutativeCipherBinary;
        this.createWithNewKeyInternal = this.ecCommutativeCipherBinary['cwrap']('CreateWithNewKey', 'number', ['number', 'number']);
        this.createFromKeyInternal = this.ecCommutativeCipherBinary['cwrap']('CreateFromKey', 'number', ['number', 'number', 'number', 'array']);
        this.encryptInternal =
            this.ecCommutativeCipherBinary
                .cwrap('Encrypt', 'number', ['number', 'array', 'number', 'number']);
        this.decryptInternal =
            this.ecCommutativeCipherBinary
                .cwrap('Decrypt', 'number', ['number', 'array', 'number', 'number']);
        this.reencryptInternal =
            this.ecCommutativeCipherBinary
                .cwrap('ReEncrypt', 'number', ['number', 'array', 'number', 'number']);
        this.hashToTheCurveInternal =
            this.ecCommutativeCipherBinary
                .cwrap('HashToTheCurve', 'number', ['number', 'array', 'number', 'number']);
        this.destroyInternal = ecCommutativeCipherBinary['cwrap']('Destroy', null, ['number']);
        this.mallocInternal =
            this.ecCommutativeCipherBinary._malloc;
        this.freeInternal = this.ecCommutativeCipherBinary._free;
    }
    /**
     * Factory function to create crypto implementation. Promise will be resolved
     * once all dependencies are initialized.
     */
    static createEcCommutativeCipherImpl() {
        return __awaiter(this, void 0, void 0, function* () {
            const ecCommutativeCipherBinary = {
                wasmBinary: Buffer.from(wasmData.EC_COMMUTATIVE_CIPHER_BASE64, 'base64')
            };
            if (typeof ec_commutative_cipher_wasm_loader_closurized_1.default !== 'function') {
                throw new Error('WASM loader is not a function.');
            }
            return new EcCommutativeCipherImpl(yield (0, ec_commutative_cipher_wasm_loader_closurized_1.default)(ecCommutativeCipherBinary));
        });
    }
    createWithNewKey(curveId, hashType) {
        return this.createWithNewKeyInternal(curveId, hashType);
    }
    createFromKey(curveId, hashType, key) {
        return this.createFromKeyInternal(curveId, hashType, key.length, key);
    }
    encrypt(ecCipher, plaintext) {
        // Allocate on heap.
        const bufPtr = this.mallocInternal(MAX_ALLOCATED_BYTES);
        const numBytes = this.encryptInternal(plaintext.length, plaintext, ecCipher, bufPtr);
        const encryption = this.ecCommutativeCipherBinary
            .HEAPU8.slice(bufPtr, bufPtr + numBytes);
        // Remove from heap.
        this.freeInternal(bufPtr);
        return encryption;
    }
    decrypt(ecCipher, ciphertext) {
        // Allocate on heap.
        const bufPtr = this.mallocInternal(MAX_ALLOCATED_BYTES);
        const numBytes = this.decryptInternal(ciphertext.length, ciphertext, ecCipher, bufPtr);
        const decryption = this.ecCommutativeCipherBinary
            .HEAPU8.slice(bufPtr, bufPtr + numBytes);
        // Remove from heap.
        this.freeInternal(bufPtr);
        return decryption;
    }
    reencrypt(ecCipher, ciphertext) {
        // Allocate on heap.
        const bufPtr = this.mallocInternal(MAX_ALLOCATED_BYTES);
        const numBytes = this.reencryptInternal(ciphertext.length, ciphertext, ecCipher, bufPtr);
        const encryption = this.ecCommutativeCipherBinary
            .HEAPU8.slice(bufPtr, bufPtr + numBytes);
        // Remove from heap.
        this.freeInternal(bufPtr);
        return encryption;
    }
    hashToTheCurve(ecCipher, input) {
        // Allocate on heap.
        const bufPtr = this.mallocInternal(MAX_ALLOCATED_BYTES);
        const numBytes = this.hashToTheCurveInternal(input.length, input, ecCipher, bufPtr);
        const hash = this.ecCommutativeCipherBinary
            .HEAPU8.slice(bufPtr, bufPtr + numBytes);
        // Remove from heap.
        this.freeInternal(bufPtr);
        return hash;
    }
    destroy(ecCipher) {
        this.destroyInternal(ecCipher);
    }
}
exports.EcCommutativeCipherImpl = EcCommutativeCipherImpl;
