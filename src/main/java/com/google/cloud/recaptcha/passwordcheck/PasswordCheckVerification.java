package com.google.cloud.recaptcha.passwordcheck;

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

import com.google.common.hash.Hashing;
import com.google.cloud.recaptcha.passwordcheck.utils.BCScryptGenerator;
import com.google.cloud.recaptcha.passwordcheck.utils.CryptoHelper;
import com.google.cloud.recaptcha.passwordcheck.utils.ScryptGenerator;
import com.google.cloud.recaptcha.passwordcheck.utils.SensitiveString;
import com.google.privacy.encryption.commutative.EcCommutativeCipher;
import com.google.privacy.encryption.commutative.SupportedCurve;
import java.util.Collection;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.function.Supplier;

/**
 * Represents a single <a href="https://cloud.google.com/recaptcha-enterprise/docs/check-passwords">
 * password check verification</a> attempt. The underlying protocol ensures that the credentials are
 * always encrypted whenever leaving the user's device; the reCAPTCHA service will not be able to
 * decrypt them.
 */
public final class PasswordCheckVerification {
  /** BouncyCastle's SCrypt Implementation. */
  static final ScryptGenerator SCRYPT_GENERATOR = new BCScryptGenerator();

  /** The curve used for the elliptic curve cipher {@link EcCommutativeCipher}. */
  static final SupportedCurve EC_CURVE = SupportedCurve.SECP256R1;

  /**
   * The username hash prefix length in bits that is expected by the reCAPTCHA Enterprise Password
   * Check service.
   */
  static final int USERNAME_HASH_PREFIX_LENGTH = 26;

  /** The username to be checked for password leaks. */
  private final String username;

  /** The {@link EcCommutativeCipher} used to encrypt/decrypt these verification credentials. */
  private final EcCommutativeCipher cipher;

  private byte[] encryptedUserCredentialsHash;
  private byte[] lookupHashPrefix;

  /** Creates a new {@link PasswordLeakVerification} instance with the given username. */
  private PasswordCheckVerification(String username) {
    this.cipher = EcCommutativeCipher.createWithNewKey(EC_CURVE);
    this.username = username;
  }

  /**
   * Returns the encrypted hashed user credentials. The encryption is performed using the instance's
   * internal cipher and the encryption key is not accessible from outside of this class to ensure
   * high privacy.
   *
   * @return byte array of the encrypted hashed credentials for this verification
   */
  public byte[] getEncryptedUserCredentialsHash() {
    return encryptedUserCredentialsHash;
  }

  /**
   * Returns the encrypted lookup hash containing the hashed user credentials. The encryption is
   * performed using the instance's internal cipher and the encryption key is not accessible from
   * outside of this class to ensure high privacy.
   *
   * @deprecated This method is no longer acceptable to get the encrypted user credentials hash.
   *     <p>Use {@link PasswordCheckVerification#getEncryptedUserCredentialsHash()} instead.
   * @return byte array of the encrypted hashed credentials for this verification
   */
  @Deprecated
  public byte[] getEncryptedLookupHash() {
    return encryptedUserCredentialsHash;
  }

  /**
   * Returns a prefix of the username hash provided for this verification. The hash prefix is
   * calculated using {@link CryptoHelper#bucketizeUsername(String, int)}}.
   */
  public byte[] getLookupHashPrefix() {
    return lookupHashPrefix;
  }

  /** Returns the cipher associated to this verification. */
  EcCommutativeCipher getCipher() {
    return cipher;
  }

  /**
   * Factory method to initialize a {@link PasswordLeakVerification} asynchronously using the
   * provided executor service.
   *
   * @return a {@link CompletableFuture} containing a {@link PasswordLeakVerification} instance on
   *     completion. Creation is asynchronous to prevent blocking the main thread with the
   *     underlying cryptographic functions required for initialization.
   */
  static CompletableFuture<PasswordCheckVerification> create(
      String username, SensitiveString password, ExecutorService executorService) {
    return CompletableFuture.supplyAsync(getCreatorSupplier(username, password), executorService);
  }

  /**
   * Returns a {@link CompletableFuture} containing a {@link PasswordLeakResult} built from the
   * server response to determine if a password was leaked or not.
   *
   * @param reEncryptedUserCredentialsHash server-side re-encrypted lookup hash. It is decrypted
   *     using the verification credentials to match it with the provided list.
   * @param encryptedLeakMatchPrefixList list of encrypted lookup hash prefixes found on the server
   *     side.
   * @return a {@link CompletableFuture} containing a {@link PasswordLeakResult} built from the
   *     server response to determine whether the associated credentials were leaked or not.
   */
  CompletableFuture<PasswordCheckResult> verify(
      final byte[] reEncryptedUserCredentialsHash,
      final Collection<byte[]> encryptedLeakMatchPrefixList,
      final ExecutorService executorService) {

    if (reEncryptedUserCredentialsHash == null) {
      throw new IllegalArgumentException("reEncryptedLookupHash cannot be null");
    }

    if (encryptedLeakMatchPrefixList == null) {
      throw new IllegalArgumentException("encryptedLeakMatchPrefixList cannot be null");
    }

    return CompletableFuture.supplyAsync(
        () -> {
          final byte[] serverEncryptedUserCredentialsHash =
              cipher.decrypt(reEncryptedUserCredentialsHash);
          final boolean credentialsLeaked =
              encryptedLeakMatchPrefixList.stream()
                  .anyMatch(prefix -> isPrefixMatch(serverEncryptedUserCredentialsHash, prefix));

          return new PasswordCheckResult(this, this.username, credentialsLeaked);
        },
        executorService);
  }

  /**
   * Returns a {@link Supplier} that creates a {@link PasswordLeakVerification} using the given
   * username and password. Since the initialization is CPU intensive due to the cryptographic
   * functions required to create the lookup hash prefix and encrypted user credentials hash, no
   * constructor is exposed publicly; instead, the create method executes the supplied function
   * asynchronously to prevent blocking the program main thread.
   *
   * @param username the username of the verification to be created
   * @param password the password of the verification to be created
   * @return a {@link Supplier} function that returns a verification after being initialized
   *     asynchronously
   */
  private static Supplier<PasswordCheckVerification> getCreatorSupplier(
      final String username, final SensitiveString password) {
    return () -> {
      PasswordCheckVerification verification = new PasswordCheckVerification(username);
      String canonicalizedUsername = CryptoHelper.canonicalizeUsername(username);

      verification.encryptedUserCredentialsHash =
          verification.cipher.encrypt(
              CryptoHelper.hashUsernamePasswordPair(
                  canonicalizedUsername, password, SCRYPT_GENERATOR));
      verification.lookupHashPrefix =
          CryptoHelper.bucketizeUsername(canonicalizedUsername, USERNAME_HASH_PREFIX_LENGTH);

      return verification;
    };
  }

  /**
   * Determines whether or not the given {@code prefix} matches with the {@code
   * serverEncryptedUserCredentialsHash}.
   *
   * @param serverEncryptedUserCredentialsHash the server-side encrypted user credentials hash
   * @param prefix single server-side generated prefix of encrypted potentially leaked credentials
   * @return whether or not {@code prefix} is a prefix of {@code serverEncryptedUserCredentialsHash}
   */
  private boolean isPrefixMatch(byte[] serverEncryptedUserCredentialsHash, byte[] prefix) {
    if (prefix.length == 0 || prefix.length > serverEncryptedUserCredentialsHash.length) {
      return false;
    }

    byte[] reHashedEncryptedUserCredentialsHash =
        Hashing.sha256().hashBytes(serverEncryptedUserCredentialsHash).asBytes();

    for (int i = 0; i < prefix.length; i++) {
      if (reHashedEncryptedUserCredentialsHash[i] != prefix[i]) {
        return false;
      }
    }

    return true;
  }
}
