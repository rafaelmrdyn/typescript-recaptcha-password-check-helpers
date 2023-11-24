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
export declare class BitPrefix {
    readonly prefix: BigInteger;
    readonly length: number;
    private static readonly BYTE_SIZE;
    private constructor();
    /**
     * Takes the bit-wise prefix of `fullBytes` with length `prefixLength` in
     * bits.
     *
     * *Note*: This will treat `fullBytes` in a big-endian fashion (i.e.
     * truncate from the back).
     *
     * *Examples*:
     *
     * - fullBytes: {0b00010001, 0b10101010}, prefixLength: 12 =>
     * 0b000100011010
     * - fullBytes: {0b00010001}, prefixLength: 8 => 0b00010001
     */
    static of(fullBytes: Uint8Array, prefixLength: number): BitPrefix;
    /** Produces binary representation of prefix. */
    toString(): string;
    /**
     * Creates a bit mask for the last byte of the prefix.
     */
    private static bitMask;
    /**
     * Produces a binary representation of the given number, conditioned to the
     * index in the prefix byte array. If it's the last index, the result will be
     * truncated to fit within the `BitArray` length.
     */
    private toBinaryStr;
}
