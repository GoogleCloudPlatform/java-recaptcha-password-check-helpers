package com.google.privacy.encryption.commutative;

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

import static com.google.common.base.StandardSystemProperty.JAVA_VM_NAME;

/**
 * Implementation of EcCommutativeCipher using native C++ code and JNI.
 *
 * <p>EcCommutativeCipherNative class with the property that K1(K2(a)) = K2(K1(a)) where K(a) is
 * encryption with the key K.
 *
 * <p>This class allows two parties to determine if they share the same value, without revealing the
 * sensitive value to each other. See the paper "Using Commutative Encryption to Share a Secret" at
 * https://eprint.iacr.org/2008/356.pdf for reference.
 *
 * <p>The encryption is performed over an elliptic curve.
 *
 * <p>Security: The provided bit security is half the number of bits of the underlying curve. For
 * example, using curve secp256r1 gives 128 bit security.
 */
public final class EcCommutativeCipherNative implements AutoCloseable {

  // Loads the native EcCommutativeCipher library for the Android environment.
  static {
    try {
      System.loadLibrary("ec_commutative_cipher_native_jni-android");
    } catch (UnsatisfiedLinkError e) {
      // Throws {@link UnsatisfiedLinkError} if the current VM is Android.
      if (JAVA_VM_NAME.value().equals("Dalvik")) {
        throw e;
      }
    }
  }

  /** List of supported underlying hash types for the commutative cipher. */
  public enum HashType {
    SHA256,
    SHA384,
    SHA512,
    SSWU_RO;
  }

  /** Memory address of the native cipher object. 0 if object is closed. */
  private long nativeHandle;

  private EcCommutativeCipherNative(long nativeHandle) {
    this.nativeHandle = nativeHandle;
  }

  /**
   * Creates an EcCommutativeCipherNative object with a new random private key based on the {@code
   * curve}. Use this method when the key is created for the first time or it needs to be refreshed.
   *
   * <p>New users should use SSWU_RO as the underlying hash function.
   */
  public static EcCommutativeCipherNative createWithNewKey(
      SupportedCurve curve, HashType hashType) {
    String curveName = curve.name();
    String hashTypeName = hashType.name();
    long nativeHandle = createWithNewKeyNative(curveName, hashTypeName);
    return new EcCommutativeCipherNative(nativeHandle);
  }

  /**
   * Creates an EcCommutativeCipherNative object with a new random private key based on the {@code
   * curve}. Use this method when the key is created for the first time or it needs to be refreshed.
   *
   * <p>The underlying hash type will be SSWU_RO.
   */
  public static EcCommutativeCipherNative createWithNewKey(SupportedCurve curve) {
    return createWithNewKey(curve, HashType.SSWU_RO);
  }

  /**
   * Creates an EcCommutativeCipherNative object from the given key. A new key should be created for
   * each session and all values should be unique in one session because the encryption is
   * deterministic. Use this when the key is stored securely to be used at different steps of the
   * protocol in the same session or by multiple processes.
   *
   * <p>New users should use SSWU_RO as the underlying hash function.
   *
   * @throws IllegalArgumentException if the key encoding is invalid.
   */
  public static EcCommutativeCipherNative createFromKey(
      SupportedCurve curve, HashType hashType, byte[] keyBytes) {
    String curveName = curve.name();
    String hashTypeName = hashType.name();
    long nativeHandle = createFromKeyNative(curveName, hashTypeName, keyBytes);
    return new EcCommutativeCipherNative(nativeHandle);
  }

  /**
   * Creates an EcCommutativeCipherNative object from the given key. A new key should be created for
   * each session and all values should be unique in one session because the encryption is
   * deterministic. Use this when the key is stored securely to be used at different steps of the
   * protocol in the same session or by multiple processes.
   *
   * <p>The underlying hash type will be SSWU_RO.
   *
   * @throws IllegalArgumentException if the key encoding is invalid.
   */
  public static EcCommutativeCipherNative createFromKey(SupportedCurve curve, byte[] keyBytes) {
    return createFromKey(curve, HashType.SSWU_RO, keyBytes);
  }

  /**
   * Releases the underlying memory held by this object. This method MUST be called when this cipher
   * is no longer needed, since native memory is not garbage-collected.
   *
   * <p>After this method is called, any further calls to the same object instance will throw an
   * IllegalStateException.
   */
  @Override
  public void close() {
    if (nativeHandle != 0) {
      closeNative(nativeHandle);
      nativeHandle = 0;
    }
  }

  /**
   * Encrypts an input with the private key, first hashing the input to the curve.
   *
   * @param plaintext bytes to encrypt
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA.
   */
  public byte[] encrypt(byte[] plaintext) {
    return encryptNative(nativeHandle, plaintext);
  }

  /**
   * Re-encrypts an encoded point with the private key.
   *
   * @param ciphertext an encoded point as defined in ANSI X9.62 ECDSA
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA
   * @throws IllegalArgumentException if the encoding is invalid or if the decoded point is not on
   *     the curve, or is the point at infinity
   */
  public byte[] reEncrypt(byte[] ciphertext) {
    return reEncryptNative(nativeHandle, ciphertext);
  }

  /**
   * Decrypts an encoded point that has been previously encrypted with the private key. Does not
   * reverse hashing to the curve.
   *
   * @param ciphertext an encoded point as defined in ANSI X9.62 ECDSA
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA
   * @throws IllegalArgumentException if the encoding is invalid or if the decoded point is not on
   *     the curve, or is the point at infinity
   */
  public byte[] decrypt(byte[] ciphertext) {
    return decryptNative(nativeHandle, ciphertext);
  }

  /**
   * Hashes bytes to a point on the elliptic curve y^2 = x^3 + ax + b over a prime field.
   *
   * @param byteId the value to hash into the curve
   * @return a point on the curve encoded in compressed form as defined in ANSI X9.62 ECDSA
   */
  public byte[] hashIntoTheCurve(byte[] byteId) {
    return hashIntoTheCurveNative(nativeHandle, byteId);
  }

  /**
   * Returns the private key bytes.
   *
   * @return the private key bytes for this EcCommutativeCipher.
   */
  public byte[] getPrivateKeyBytes() {
    return getPrivateKeyBytesNative(nativeHandle);
  }

  private static native long createWithNewKeyNative(String curveName, String hashTypeName);

  private static native long createFromKeyNative(
      String curveName, String hashTypeName, byte[] keyBytes);

  private native void closeNative(long handle);

  private native byte[] encryptNative(long handle, byte[] plaintext);

  private native byte[] reEncryptNative(long handle, byte[] ciphertext);

  private native byte[] decryptNative(long handle, byte[] ciphertext);

  private native byte[] hashIntoTheCurveNative(long handle, byte[] byteId);

  private native byte[] getPrivateKeyBytesNative(long handle);
}
