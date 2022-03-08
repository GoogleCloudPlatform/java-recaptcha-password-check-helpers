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

import com.google.common.collect.Sets;
import java.util.Set;

/**
 * A runtime exception that outputs a given exception stack trace but omits the messages as they
 * could contain sensitive data. Use this for sensitive code that could inadvertently leak sensitive
 * data (e.g. decrypted passwords) in exception messages.
 */
public final class MessageStrippingException extends RuntimeException {

  /**
   * Creates a new {@code MessageStrippingException} that encapsulates a {@link Throwable} that
   * could potentially contain sensistive data and strips its content.
   */
  public MessageStrippingException(String message, Throwable cause) {
    super(message + "\nOriginal stack trace:\n" + extractOriginalStackTrace(cause));
  }

  private static String extractOriginalStackTrace(Throwable cause) {
    StringBuilder stackTrace = new StringBuilder();
    addStackTrace(cause, Sets.<Throwable>newHashSet(), stackTrace, "");
    return stackTrace.toString();
  }

  private static void addStackTrace(
      Throwable cause, Set<Throwable> alreadySeen, StringBuilder stackTrace, String indent) {
    Throwable currentThrowable = cause;

    while (currentThrowable != null) {
      stackTrace.append(currentThrowable.getClass().getName());
      if (!alreadySeen.add(currentThrowable)) {
        break;
      }

      for (StackTraceElement stackElement : currentThrowable.getStackTrace()) {
        stackTrace.append('\n').append(indent).append('\t').append(stackElement);
      }
      for (Throwable suppressedThrowable : currentThrowable.getSuppressed()) {
        stackTrace.append('\n').append(indent).append('\t').append("Suppressed: ");
        addStackTrace(suppressedThrowable, alreadySeen, stackTrace, indent + "\t");
      }
      currentThrowable = currentThrowable.getCause();
      if (currentThrowable != null) {
        stackTrace.append('\n').append(indent).append("Caused by: ");
      }
    }
  }
}
