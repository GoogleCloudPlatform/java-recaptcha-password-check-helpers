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

/**
 * Represents a password check result obtained after a {@link PasswordLeakVerification} is requested
 * to reCAPTCHA Enterprise.
 */
public final class PasswordCheckResult {

  /** Username of the result. */
  private final String username;

  /** Whether or not the credentials for the verification are leaked. */
  private final boolean credentialsLeaked;

  /** The verification this result is associated to. */
  private final PasswordCheckVerification verification;

  PasswordCheckResult(
      PasswordCheckVerification verification, String username, boolean credentialsLeaked) {
    this.verification = verification;
    this.username = username;
    this.credentialsLeaked = credentialsLeaked;
  }

  /** Returns the {@link PasswordLeakVerification} associated to this instance. */
  public PasswordCheckVerification getPasswordLeakVerification() {
    return verification;
  }

  /** Returns the username associated to this instance. */
  public String getUsername() {
    return username;
  }

  /** Returns whether or not credentials were leaked in the associated verification. */
  public boolean areCredentialsLeaked() {
    return credentialsLeaked;
  }
}
