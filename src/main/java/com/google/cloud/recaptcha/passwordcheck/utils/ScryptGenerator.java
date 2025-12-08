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

/** Interface that exposes a method to generate a Scrypt hash with a given implementation. */
@Immutable
public interface ScryptGenerator {

  /**
   * Calculates a Scrypt hash given a plain text and extra parameters.
   *
   * @param password the plain text password to hash
   * @param salt the salt to use for the hash
   * @param cpuMemCost the CPU memory cost of the hash
   * @param blockSize the block size of the hash
   * @param parallelization the parallelization of the hash
   * @param desiredKeyLength the desired key length of the hash
   * @return the Scrypt hash of the plain text password
   */
  byte[] generate(
      byte[] password,
      byte[] salt,
      int cpuMemCost,
      int blockSize,
      int parallelization,
      int desiredKeyLength);
}
