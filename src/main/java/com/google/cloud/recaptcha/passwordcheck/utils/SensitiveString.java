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

/**
 * Wraps a {@link String} that contains sensitive information.
 *
 * <p>This prevents it from accidentally appearing in stack traces.
 */
public final class SensitiveString {

  private final String value;

  private SensitiveString(String value) {
    this.value = value;
  }

  public static SensitiveString of(String value) {
    return new SensitiveString(value);
  }

  public String getValue() {
    return value;
  }

  @Override
  public final String toString() {
    return "[REDACTED SENSITIVE STRING]";
  }

  public final boolean isEmpty() {
    try {
      return getValue().isEmpty();
    } catch (Throwable e) {
      throw new IllegalStateException("This message was stripped to protect sensitive data.", e);
    }
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

  @Override
  public boolean equals(Object object) {
    if (object instanceof SensitiveString) {
      SensitiveString that = (SensitiveString) object;
      return this.value.equals(that.value);
    }
    return false;
  }
}
