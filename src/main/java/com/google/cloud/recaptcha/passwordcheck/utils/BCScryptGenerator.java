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

import com.google.errorprone.annotations.Immutable;
import org.bouncycastle.crypto.generators.SCrypt;

/** Scrypt generator using BouncyCastle's implementation. */
@Immutable
public final class BCScryptGenerator implements ScryptGenerator {

  /** Calculates the Scrypt hash of the given plaintext with the parameters. */
  @Override
  public byte[] generate(
      byte[] plaintext,
      byte[] salt,
      int cpuMemCost,
      int blockSize,
      int parallelization,
      int desiredKeyLength) {
    return SCrypt.generate(
        plaintext, salt, cpuMemCost, blockSize, parallelization, desiredKeyLength);
  }
}
