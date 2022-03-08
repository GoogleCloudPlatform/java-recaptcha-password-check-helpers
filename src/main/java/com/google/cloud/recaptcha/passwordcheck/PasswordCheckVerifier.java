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

import com.google.cloud.recaptcha.passwordcheck.utils.SensitiveString;
import java.util.Collection;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * This class that exposes functionality to: 1) build a new {@link PasswordLeakVerification} which
 * holds the parameters for performing a request to <a href="#">reCAPTCHA Enterprise Password Leak
 * Verification</a> and 2) parse the server response to determine if a username/password pair has
 * been leaked.
 */
public final class PasswordCheckVerifier {

  /** Number of threads for the default executor service. */
  private static final int DEFAULT_N_THREADS = 10;

  /** Executor service to handle CPU-intensive tasks. */
  private final ExecutorService executorService;

  /**
   * Creates a new {@link PasswordLeakVerifier} instance.
   *
   * @param executorService used to execute costly cryptographic functions in separate threads
   */
  public PasswordCheckVerifier(ExecutorService executorService) {
    this.executorService = executorService;
  }

  /**
   * Creates a new {@link PasswordLeakVerifier} instance. Cryptographic functions are executed in
   * separate threads through an internal ExecutorService.
   */
  public PasswordCheckVerifier() {
    this.executorService = Executors.newFixedThreadPool(DEFAULT_N_THREADS);
  }

  /**
   * Creates a new {@link PasswordLeakVerification} instance. This is executed in a separate thread
   * to avoid blocking the main thread with the costly cryptographic functions that are executed
   * internally.
   *
   * <p>The created {@link PasswordLeakVerification} must be kept to verify the response of the
   * server since a unique encryption key is generated internally for such validation.
   *
   * @param username the username to be checked for password leaks
   * @param password the password associated to the username to check if it has been leaked
   * @return a {@link CompletableFuture} containing a {@link PasswordLeakVerification} on completion
   */
  public CompletableFuture<PasswordCheckVerification> createVerification(
      String username, String password) {
    return PasswordCheckVerification.create(username, SensitiveString.of(password), executorService)
        .toCompletableFuture();
  }

  /**
   * Parses the result of a reCAPTCHA Password Leak Verification request and responds with a {@link
   * CompletableFuture} containing a {@link PasswordLeakResult} on completion.
   *
   * <p>This verification is executed in a separate thread to avoid blocking the main thread with
   * the underlying cryptographic functions executed.
   *
   * <p>Note: The parameters {@code reEncryptedLookupHash} and {@code encryptedLeakMatchPrefixList}
   * are obtained as part of the server response to the password leak verification request.
   *
   * @param verification the instance to be verified
   * @param reEncryptedLookupHash server-side re-encrypted lookup hash. It is decrypted using the
   *     client key to validate if there is a password leak.
   * @param encryptedLeakMatchPrefixList list of server-side encrypted possible leaks found. To be
   *     verified using the decryption of {@code reEncryptedLookupHash}
   * @return a {@link CompletableFuture} containing the result of the password leak verification
   */
  public CompletableFuture<PasswordCheckResult> verify(
      PasswordCheckVerification verification,
      final byte[] reEncryptedLookupHash,
      final Collection<byte[]> encryptedLeakMatchPrefixList) {
    return verification
        .verify(reEncryptedLookupHash, encryptedLeakMatchPrefixList, executorService)
        .toCompletableFuture();
  }
}
