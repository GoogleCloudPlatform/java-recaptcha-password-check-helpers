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

/** Simple utility class to extract a username from an email address. */
final class EmailAddress {

  private final String emailAddress;
  private final String username;

  /** Creates a new instance with the given {@code emailAddress}. */
  public EmailAddress(String emailAddress) {
    this.emailAddress = emailAddress;

    if (isValid()) {
      this.username = emailAddress.substring(0, emailAddress.indexOf('@'));
    } else {
      this.username = emailAddress;
    }
  }

  public boolean isValid() {
    return this.emailAddress.contains("@");
  }

  public String getUser() {
    return this.username;
  }
}
