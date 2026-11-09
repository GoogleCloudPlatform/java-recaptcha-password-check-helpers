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

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class EmailAddressTest {

  @Test
  public void validEmail_extractsUser() {
    EmailAddress email = new EmailAddress("user@example.com");
    assertThat(email.isValid()).isTrue();
    assertThat(email.getUser()).isEqualTo("user");
  }

  @Test
  public void plainUsername_isNotValidEmail() {
    EmailAddress email = new EmailAddress("plain_username");
    assertThat(email.isValid()).isFalse();
    assertThat(email.getUser()).isEqualTo("plain_username");
  }

  @Test
  public void multipleAtSigns_splitsAtLastAt() {
    EmailAddress email = new EmailAddress("te@st@mail.com");
    assertThat(email.isValid()).isTrue();
    assertThat(email.getUser()).isEqualTo("te@st");
  }
}
