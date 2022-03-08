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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Ascii;
import com.google.cloud.recaptcha.passwordcheck.utils.EmailAddress;
import com.google.common.hash.Hashing;
import com.google.common.math.IntMath;
import com.google.common.primitives.Bytes;
import com.google.cloud.recaptcha.passwordcheck.utils.MessageStrippingException;
import com.google.cloud.recaptcha.passwordcheck.utils.SensitiveString;
import com.google.privacy.encryption.commutative.EcCommutativeCipher;

/**
 * Common crypto utils, exposes methods to generate the parameters of password leak check requests
 * and validate the responses.
 */
public abstract class CryptoHelper {

  private static final int SCRYPT_PASSWORD_HASH_CPU_MEM_COST = IntMath.pow(2, 12);
  private static final int SCRYPT_PASSWORD_HASH_BLOCK_SIZE = 8;
  private static final int SCRYPT_PASSWORD_HASH_PARALLELIZATION = 1;
  private static final int SCRYPT_PASSWORD_HASH_KEY_LENGTH = 32;

  // Constant salt added to the password hash on top of username. This adds a tiny bit of security
  // to the hashes - requiring and attacker to first create a rainbow table for this salt.
  private static final byte[] PASSWORD_HASH_CONSTANT_SALT = {
    (byte) 0x30, (byte) 0x76, (byte) 0x2A, (byte) 0xD2, (byte) 0x3F, (byte) 0x7B, (byte) 0xA1,
    (byte) 0x9B, (byte) 0xF8, (byte) 0xE3, (byte) 0x42, (byte) 0xFC, (byte) 0xA1, (byte) 0xA7,
    (byte) 0x8D, (byte) 0x06, (byte) 0xE6, (byte) 0x6B, (byte) 0xE4, (byte) 0xDB, (byte) 0xB8,
    (byte) 0x4F, (byte) 0x81, (byte) 0x53, (byte) 0xC5, (byte) 0x03, (byte) 0xC8, (byte) 0xDB,
    (byte) 0xBd, (byte) 0xDE, (byte) 0xA5, (byte) 0x20
  };

  // Constant salt added to the username hash. This adds a tiny bit of security to the hashes
  // requiring and attacker to first create a rainbow table for this salt.
  private static final byte[] USERNAME_HASH_CONSTANT_SALT = {
    (byte) 0xC4, (byte) 0x94, (byte) 0xA3, (byte) 0x95, (byte) 0xF8, (byte) 0xC0, (byte) 0xE2,
    (byte) 0x3E, (byte) 0xA9, (byte) 0x23, (byte) 0x04, (byte) 0x78, (byte) 0x70, (byte) 0x2C,
    (byte) 0x72, (byte) 0x18, (byte) 0x56, (byte) 0x54, (byte) 0x99, (byte) 0xB3, (byte) 0xE9,
    (byte) 0x21, (byte) 0x18, (byte) 0x6C, (byte) 0x21, (byte) 0x1A, (byte) 0x01, (byte) 0x22,
    (byte) 0x3C, (byte) 0x45, (byte) 0x4A, (byte) 0xFA
  };

  /**
   * Produces username hash. {@code canonicalizedUsername} is pre-canonicalized using {@link
   * #canonicalizeUsername}.
   *
   * <p>NOTE: the username hash is not safe against offline attacks, but that's acceptable since the
   * client only exposes a limited number of bits about it. The server itself never returns a
   * username hash.
   */
  public static byte[] hashUsername(String canonicalizedUsername) {
    return Hashing.sha256()
        .hashBytes(Bytes.concat(canonicalizedUsername.getBytes(UTF_8), USERNAME_HASH_CONSTANT_SALT))
        .asBytes();
  }

  /**
   * Produces a username-password pair hash. {@code canonicalizedUsername} is pre-canonicalized
   * using {@link #canonicalizeUsername}.
   *
   * <p>NOTE: this hash is relatively safe against offline attacks. However, a second layer of
   * protection comes from the fact that these hashes are never returned in cleartext to the client,
   * but rather only encrypted with a commutative cipher. Hence, the slowness of this hashing
   * algorithm is not as critical.
   *
   * <p>PERFORMANCE: this is a very resource-intensive operation, since the hashing algorithm used
   * is very time and memory complex. If multiple hashes are done, this should be executed outside
   * of the request thread.
   */
  public static byte[] hashUsernamePasswordPair(
      String canonicalizedUsername, SensitiveString password, ScryptGenerator scryptGenerator) {
    byte[] usernameBytes = canonicalizedUsername.getBytes(UTF_8);

    try {
      return scryptGenerator.generate(
          Bytes.concat(usernameBytes, password.getValue().getBytes(UTF_8)),
          Bytes.concat(usernameBytes, PASSWORD_HASH_CONSTANT_SALT),
          SCRYPT_PASSWORD_HASH_CPU_MEM_COST,
          SCRYPT_PASSWORD_HASH_BLOCK_SIZE,
          SCRYPT_PASSWORD_HASH_PARALLELIZATION,
          SCRYPT_PASSWORD_HASH_KEY_LENGTH);
    } catch (Throwable e) {
      // This stack trace is stripped to protect sensitive data
      throw new MessageStrippingException("Computing the password hash failed.", e);
    }
  }

  /**
   * Canonicalizes a username by lower-casing ASCII characters, stripping a mail-address host in
   * case the username is a mail address, and stripping dots.
   */
  public static String canonicalizeUsername(String username) {
    EmailAddress emailAddress = new EmailAddress(username);
    if (emailAddress.isValid()) {
      username = emailAddress.getUser();
    }

    return Ascii.toLowerCase(username.replace(".", ""));
  }

  /**
   * Canonicalizes and hashes a username.
   *
   * <p>Convenience method that wraps {@link #canonicalizeUsername(String)} and {@link
   * #hashUsername(String)} and returns the result as a byte[].
   */
  public static byte[] canonicalizeAndHashUsername(String username) {
    String canonicalizeUsername = canonicalizeUsername(username);
    return hashUsername(canonicalizeUsername);
  }

  /** Hash the encrypted username password pair to achieve uniform distribution. */
  public static byte[] hashBlindedHash(byte[] blindedHash) {
    return Hashing.sha256().hashBytes(blindedHash).asBytes();
  }

  /**
   * Uses the given {@code cipher} to encrypt a hash of the {@code canonicalizedUsername} and {@code
   * password}.
   */
  public static byte[] computeEncryptedLookupHash(
      String canonicalizedUsername,
      SensitiveString password,
      EcCommutativeCipher cipher,
      ScryptGenerator scryptGenerator) {
    return cipher.encrypt(
        hashUsernamePasswordPair(canonicalizedUsername, password, scryptGenerator));
  }

  /**
   * Reverse the client-side encryption of the lookup hash and then hash the result. This hashing is
   * necessary for equal distribution of the database. The server does this for all returned leak
   * matches. Hence the client has to do the same.
   */
  public static byte[] decryptReencryptedLookupHash(
      byte[] reencryptedLookupHash, EcCommutativeCipher cipher) {
    return hashBlindedHash(cipher.decrypt(reencryptedLookupHash));
  }

  /**
   * Returns a byte array containing the prefix of the hashed {@code canonicalizedUsername} with the
   * given length.
   */
  public static byte[] bucketizeUsername(
      String canonicalizedUsername, int allowedUsernameHashPrefixLength) {
    return BitPrefix.of(hashUsername(canonicalizedUsername), allowedUsernameHashPrefixLength)
        .toByteArray();
  }
}
