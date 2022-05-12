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
import static org.junit.Assert.assertThrows;

import java.util.concurrent.ExecutionException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PasswordCheckVerifierTest {
  @Test
  public void createVerification_succeeds() throws ExecutionException, InterruptedException {
    PasswordCheckVerifier verifier = new PasswordCheckVerifier();
    PasswordCheckVerification verification =
        verifier.createVerification("username", "password").get();
    assertThat(verification.getEncryptedUserCredentialsHash().length).isGreaterThan(0);
    assertThat(verification.getLookupHashPrefix().length).isGreaterThan(0);
  }

  @Test
  public void createVerificationWithNullUsername_throwIllegalArgumentException() {
    PasswordCheckVerifier verifier = new PasswordCheckVerifier();
    assertThrows(
        IllegalArgumentException.class, () -> verifier.createVerification(null, "password").get());
  }

  @Test
  public void createVerificationWithNullPassword_throwIllegalArgumentException() {
    PasswordCheckVerifier verifier = new PasswordCheckVerifier();
    assertThrows(
        IllegalArgumentException.class, () -> verifier.createVerification("username", null).get());
  }

  @Test
  public void createVerificationWithEmptyUsername_throwIllegalArgumentException() {
    PasswordCheckVerifier verifier = new PasswordCheckVerifier();
    assertThrows(
        IllegalArgumentException.class, () -> verifier.createVerification("", "password").get());
  }

  @Test
  public void createVerificationWithEmptyPassword_throwIllegalArgumentException() {
    PasswordCheckVerifier verifier = new PasswordCheckVerifier();
    assertThrows(
        IllegalArgumentException.class, () -> verifier.createVerification("username", "").get());
  }
}
