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

import static com.google.common.truth.Truth.assertThat;
import static java.util.Arrays.stream;
import static org.junit.Assert.assertThrows;

import com.google.common.hash.Hashing;
import com.google.cloud.recaptcha.passwordcheck.utils.BCScryptGenerator;
import com.google.cloud.recaptcha.passwordcheck.utils.CryptoHelper;
import com.google.cloud.recaptcha.passwordcheck.utils.ScryptGenerator;
import com.google.cloud.recaptcha.passwordcheck.utils.SensitiveString;
import com.google.privacy.encryption.commutative.EcCommutativeCipher;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class PasswordCheckVerificationTest {

  private static final ScryptGenerator SCRYPT_GENERATOR = new BCScryptGenerator();
  private static final String TEST_USERNAME = "foo";
  private static final String TEST_PASSWORD = "bar";
  private static final Credentials[] TEST_MATCHING_USERNAME_LIST = {
    new Credentials(TEST_USERNAME, TEST_PASSWORD), new Credentials("baz", "pass")
  };
  private static final Credentials[] TEST_NOT_MATCHING_USERNAME_LIST = {
    new Credentials("foo", "diff_password"), new Credentials("baz", "pass")
  };

  @Test
  public void verify_returnsLeak() throws ExecutionException, InterruptedException {
    final PasswordCheckVerification verification = createVerification();
    final TestServerResponse response =
        new TestServerResponse(verification, TEST_MATCHING_USERNAME_LIST);
    assertThat(response.checkCredentialsLeaked(verification)).isTrue();
  }

  @Test
  public void verify_returnsNoLeak() throws ExecutionException, InterruptedException {
    final PasswordCheckVerification verification = createVerification();
    final TestServerResponse response =
        new TestServerResponse(verification, TEST_NOT_MATCHING_USERNAME_LIST);
    assertThat(response.checkCredentialsLeaked(verification)).isFalse();
  }

  @Test
  public void verify_emptyEncryptedLeakMatchPrefix_returnsNoLeak()
      throws ExecutionException, InterruptedException {
    final PasswordCheckVerification verification = createVerification();
    final TestServerResponse response = new TestServerResponse(verification, new Credentials[] {});
    assertThat(response.checkCredentialsLeaked(verification)).isFalse();
  }

  @Test
  public void verify_nullReEncryptedLookupHash_throwsException()
      throws ExecutionException, InterruptedException {
    final PasswordCheckVerification verification = createVerification();
    assertThrows(
        IllegalArgumentException.class,
        () -> verification.verify(null, new ArrayList<>(), Executors.newCachedThreadPool()));
  }

  @Test
  public void verify_nullEncryptedLeakMatchPrefixList_throwsException()
      throws ExecutionException, InterruptedException {
    final PasswordCheckVerification verification = createVerification();
    assertThrows(
        IllegalArgumentException.class,
        () -> verification.verify(new byte[] {}, null, Executors.newCachedThreadPool()));
  }

  // --- Utility methods --- //

  /** Crates a new {@link PasswordLeakVerification} with fixed test parameters */
  private PasswordCheckVerification createVerification()
      throws ExecutionException, InterruptedException {
    PasswordCheckVerifier passwordLeak = new PasswordCheckVerifier();

    return passwordLeak.createVerification(TEST_USERNAME, TEST_PASSWORD).get();
  }

  /** Wrapper class to hold the data necessary to simulate a server response */
  private static final class TestServerResponse {
    final EcCommutativeCipher serverCipher;
    final byte[] serverReEncryptedLookupHash;
    final List<byte[]> encryptedLeakMatchPrefixTestList;

    /**
     * Creates a "server-side" cipher and uses it to re-encrypt the verification lookup prefix and a
     * list of prefixes supposedly found by the server.
     *
     * @param verification test verification
     * @param credentialsList test list of credentials
     */
    TestServerResponse(PasswordCheckVerification verification, Credentials[] credentialsList) {
      this.serverCipher = EcCommutativeCipher.createWithNewKey(PasswordCheckVerification.EC_CURVE);
      this.serverReEncryptedLookupHash =
          serverCipher.reEncrypt(verification.getEncryptedLookupHash());

      this.encryptedLeakMatchPrefixTestList =
          stream(credentialsList)
              .map(this::serverEncryptAndRehash)
              .map(a -> Arrays.copyOf(a, 20))
              .collect(Collectors.toList());
    }

    private byte[] serverEncryptAndRehash(Credentials credentials) {
      byte[] serverEncrypted =
          serverCipher.encrypt(
              CryptoHelper.hashUsernamePasswordPair(
                  credentials.username,
                  SensitiveString.of(credentials.password),
                  SCRYPT_GENERATOR));
      return Hashing.sha256().hashBytes(serverEncrypted).asBytes();
    }

    boolean checkCredentialsLeaked(PasswordCheckVerification verification)
        throws ExecutionException, InterruptedException {

      final PasswordCheckResult result =
          verification
              .verify(
                  this.serverReEncryptedLookupHash,
                  this.encryptedLeakMatchPrefixTestList,
                  Executors.newSingleThreadExecutor())
              .toCompletableFuture()
              .get();

      return result.areCredentialsLeaked();
    }
  }

  private static class Credentials {
    final String username;
    final String password;

    Credentials(String username, String password) {
      this.username = username;
      this.password = password;
    }
  }
}
