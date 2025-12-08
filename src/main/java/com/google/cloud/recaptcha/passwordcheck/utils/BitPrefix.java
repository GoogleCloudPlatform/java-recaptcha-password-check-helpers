package com.google.cloud.recaptcha.passwordcheck.utils;

// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;
import com.google.errorprone.annotations.Immutable;
import java.math.BigInteger;

/** Simple abstraction for computing and handling prefixes. */
@Immutable
@AutoValue
public abstract class BitPrefix {

  /** Internal {@link BigInteger} representation of the prefix. */
  abstract BigInteger bigInteger();

  /**
   * Returns the prefix length.
   *
   * @return the prefix length
   */
  public abstract int length();

  /**
   * Takes the bit-wise prefix of {@code fullBytes} with length {@code prefixLength} in bits.
   *
   * <p>Note: This will treat {@code fullBytes} in a big-endian fashion (i.e. truncate from the
   * back).
   *
   * <p>Examples:
   *
   * <ul>
   *   <li>fullBytes: {0b00010001, 0b10101010}, prefixLength: 12 => 0b000100011010
   *   <li>fullBytes: {0b00010001}, prefixLength: 8 => 0b00010001
   * </ul>
   *
   * @param fullBytes the full bytes to take the prefix of
   * @param prefixLength the length of the prefix in bits
   * @return the {@code BitPrefix} of the full bytes
   */
  public static BitPrefix of(byte[] fullBytes, int prefixLength) {
    Preconditions.checkArgument(fullBytes.length * Byte.SIZE >= prefixLength);

    return new AutoValue_BitPrefix(
        new BigInteger(1, fullBytes).shiftRight((fullBytes.length * Byte.SIZE) - prefixLength),
        prefixLength);
  }

  /**
   * Takes the bit-wise prefix of this prefix with length {@code prefixLength} in bits.
   *
   * <p>Examples:
   *
   * <ul>
   *   <li>this: 0b1010101010, prefixLength: 8 => 0b10101010
   *   <li>this: 0b10101, prefixLength: 0 => Empty prefix
   * </ul>
   *
   * @param prefixLength the length of the prefix in bits
   * @return the truncated {@code BitPrefix}
   */
  public BitPrefix truncate(int prefixLength) {
    Preconditions.checkArgument(length() >= prefixLength);

    return new AutoValue_BitPrefix(bigInteger().shiftRight(length() - prefixLength), prefixLength);
  }

  /**
   * Returns the expanded prefix.
   *
   * <p>Examples:
   *
   * <ul>
   *   <li>prefix: 0b1010, lengthInBytes: 2, fillBit: false => {0b10100000, 0b00000000}
   *   <li>prefix: 0b1010, lengthInBytes: 2, fillBit: true => {0b10101111, 0b11111111}
   *   <li>prefix: 0b1010, lengthInBytes: 2, fillBit: true => {0b10101111, 0b11111111}
   * </ul>
   *
   * @param prefixLength the length of the prefix in bits
   * @param fillBit whether to fill the trailing bits with 1s
   * @return the expanded {@code BitPrefix}
   */
  public BitPrefix expand(int prefixLength, boolean fillBit) {
    Preconditions.checkArgument(prefixLength >= length());

    BigInteger expandedBigInt = bigInteger().shiftLeft(prefixLength - length());

    // Create trailing 1s to fill up remaining bits.
    if (fillBit) {
      BigInteger bitMask =
          BigInteger.ONE.shiftLeft(prefixLength - length()).subtract(BigInteger.ONE);

      expandedBigInt = expandedBigInt.or(bitMask);
    }

    return new AutoValue_BitPrefix(expandedBigInt, prefixLength);
  }

  /**
   * Returns the prefix as a byte array. The resulting byte array has the most significant prefix
   * bit set as the most significant bit in the first array entry (big-endian style). Trailing bits
   * in the last byte are filled up with 0s.
   *
   * <p>Examples:
   *
   * <ul>
   *   <li>this: 0b0101 => {0b01010000}
   *   <li>this: 0b01010101 => {0b01010101}
   * </ul>
   *
   * @return the prefix as a byte array
   */
  public byte[] toByteArray() {
    return toByteArray(false);
  }

  /**
   * Returns the prefix as a byte array. The resulting byte array has the most significant prefix
   * bit set as the most significant bit in the first array entry (big-endian style). Trailing bits
   * in the last byte are filled up with {@code fillBit}.
   *
   * <p>Examples:
   *
   * <ul>
   *   <li>this: 0b0101, fillBit: false => {0b01010000}
   *   <li>this: 0b0101, fillBit: true => {0b01011111}
   *   <li>this: 0b01010101, fillBit: true/false => {0b01010101}
   * </ul>
   *
   * @param fillBit whether to fill the trailing bits with 1s
   * @return the prefix as a byte array
   */
  public byte[] toByteArray(boolean fillBit) {
    return toByteArray((length() + Byte.SIZE - 1) / Byte.SIZE, fillBit);
  }

  /**
   * Returns the prefix as a byte array of length {@code arrayLength}. The resulting byte array has
   * the most significant prefix bit set as the most significant bit in the first array entry
   * (big-endian style). Trailing bits in the array are filled up with {@code fillBit}.
   *
   * <p>Examples:
   *
   * <ul>
   *   <li>this: 0b0101, arrayLength: 1, fillBit: false => {0b01010000}
   *   <li>this: 0b0101, arrayLength: 1, fillBit: true => {0b01011111}
   *   <li>this: 0b0101, arrayLength: 2, fillBit: true => {0b01011111, 0b11111111}
   *   <li>this: 0b01010101, arrayLength: 1, fillBit: true/false => {0b01010101}
   * </ul>
   *
   * @param arrayLength the length of the array
   * @param fillBit whether to fill the trailing bits with 1s
   * @return the prefix as a byte array
   */
  public byte[] toByteArray(int arrayLength, boolean fillBit) {
    Preconditions.checkArgument(
        arrayLength >= (length() + Byte.SIZE - 1) / Byte.SIZE,
        "arrayLength is not allowed to be shorter than the prefix.");

    byte[] result = new byte[arrayLength];

    // Make sure to shift the most significant bit to the first position in the resulting byte
    // array.
    byte[] bytes = this.expand(arrayLength * Byte.SIZE, fillBit).bigInteger().toByteArray();

    // Account for a leading sign-only byte produced by BigInteger.
    int bytesContentLength = bytes[0] == 0 ? bytes.length - 1 : bytes.length;

    System.arraycopy(
        bytes,
        bytes.length - bytesContentLength,
        result,
        arrayLength - bytesContentLength,
        bytesContentLength);

    return result;
  }

  /** Produce binary representation of prefix. */
  @Override
  public final String toString() {
    if (length() == 0) {
      return "Empty prefix";
    }

    String s = bigInteger().toString(2);
    StringBuilder builder = new StringBuilder("0b");
    for (int i = 0; i < length() - s.length(); i++) {
      builder.append('0');
    }
    builder.append(s);
    return builder.toString();
  }
}
