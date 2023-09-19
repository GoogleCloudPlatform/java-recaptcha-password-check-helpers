#include <cstdint>
#include <memory>
#include <string>

#include "privacy/blinders/cpp/crypto/big_num.h"
#include "privacy/blinders/cpp/public/ec_commutative_cipher.h"
#include "privacy/private_membership/jni/jni_util.h"
#include "third_party/absl/status/status.h"
#include "third_party/java/jdk/include/jni.h"
#include "third_party/java/jdk/include/linux/jni_md.h"
#include "third_party/openssl/nid.h"
#include "util/java/jni_helper.h"

#define JFUN(METHOD_NAME) \
  Java_com_google_privacy_blinders_encryption_commutative_EcCommutativeCipherNative_##METHOD_NAME  // NOLINT

using blinders::ECCommutativeCipher;
using private_membership::jni::ThrowAssertionError;
using private_membership::jni::ThrowIllegalArgumentException;

// Assigns a pointer to the client to the address pointed at by addr and returns
// true, or throws a Java exception and returns false. If this returns false,
// return to Java immediately.
bool AssignCipherOrThrow(JNIEnv* env, jlong handle,
                         ECCommutativeCipher** addr) {
  *addr = reinterpret_cast<ECCommutativeCipher*>(handle);
  if (*addr == nullptr) {
    util::java::ThrowingJniHelper jni_helper(env);
    ThrowAssertionError(&jni_helper, "Native method called for closed client");
    return false;
  }
  return true;
}

extern "C" JNIEXPORT jlong JNICALL
JFUN(createWithNewKeyNative)(JNIEnv* env, jclass jni_class_ignored,
                             jstring curve_name, jstring hash_type_name) {
  util::java::ThrowingJniHelper jni_helper(env);
  std::string curve_name_str = jni_helper.JStringToString(curve_name);
  std::string hash_type_name_str = jni_helper.JStringToString(hash_type_name);
  int curve_id;
  if (curve_name_str == "SECP256R1") {
    curve_id = NID_X9_62_prime256v1;
  } else if (curve_name_str == "SECP384R1") {
    curve_id = NID_secp384r1;
  } else {
    ThrowIllegalArgumentException(&jni_helper, "Invalid curve");
    return 0;
  }
  ECCommutativeCipher::HashType hash_type;
  if (hash_type_name_str == "SHA256") {
    hash_type = ECCommutativeCipher::HashType::SHA256;
  } else if (hash_type_name_str == "SHA384") {
    hash_type = ECCommutativeCipher::HashType::SHA384;
  } else if (hash_type_name_str == "SHA512") {
    hash_type = ECCommutativeCipher::HashType::SHA512;
  } else {
    ThrowIllegalArgumentException(&jni_helper, "Invalid hash type");
    return 0;
  }
  ::blinders::StatusOr<std::unique_ptr<ECCommutativeCipher>> cipher =
      ECCommutativeCipher::CreateWithNewKey(curve_id, hash_type);
  if (!cipher.ok()) {
    ThrowIllegalArgumentException(
        &jni_helper, "Unable to create ECCommutativeCipher object: %s",
        cipher.status().ToString());
    return 0;
  }
  ECCommutativeCipher* ptr = cipher->release();
  return reinterpret_cast<int64_t>(ptr);
}

extern "C" JNIEXPORT jlong JNICALL JFUN(createFromKeyNative)(
    JNIEnv* env, jclass jni_class_ignored, jstring curve_name,
    jstring hash_type_name, jbyteArray key_bytes) {
  util::java::ThrowingJniHelper jni_helper(env);
  std::string curve_name_str = jni_helper.JStringToString(curve_name);
  std::string hash_type_name_str = jni_helper.JStringToString(hash_type_name);
  int curve_id;
  if (curve_name_str == "SECP256R1") {
    curve_id = NID_X9_62_prime256v1;
  } else if (curve_name_str == "SECP384R1") {
    curve_id = NID_secp384r1;
  } else {
    ThrowIllegalArgumentException(&jni_helper, "Invalid curve");
    return 0;
  }
  ECCommutativeCipher::HashType hash_type;
  if (hash_type_name_str == "SHA256") {
    hash_type = ECCommutativeCipher::HashType::SHA256;
  } else if (hash_type_name_str == "SHA384") {
    hash_type = ECCommutativeCipher::HashType::SHA384;
  } else if (hash_type_name_str == "SHA512") {
    hash_type = ECCommutativeCipher::HashType::SHA512;
  } else {
    ThrowIllegalArgumentException(&jni_helper, "Invalid hash type");
    return 0;
  }
  std::string key_bytes_str = jni_helper.ByteArrayToString(key_bytes);
  ::blinders::StatusOr<std::unique_ptr<ECCommutativeCipher>> cipher =
      ECCommutativeCipher::CreateFromKey(curve_id, key_bytes_str, hash_type);
  if (!cipher.ok()) {
    ThrowIllegalArgumentException(
        &jni_helper, "Unable to create ECCommutativeCipher object: %s",
        cipher.status().ToString());
    return 0;
  }
  ECCommutativeCipher* ptr = cipher->release();
  return reinterpret_cast<int64_t>(ptr);
}

extern "C" JNIEXPORT void JNICALL JFUN(closeNative)(JNIEnv* env,
                                                    jclass jni_class_ignored,
                                                    jlong handle) {
  ECCommutativeCipher* cipher;
  if (!AssignCipherOrThrow(env, handle, &cipher)) {
    return;
  }
  delete cipher;
}

extern "C" JNIEXPORT jbyteArray JNICALL JFUN(encryptNative)(
    JNIEnv* env, jclass jni_class_ignored, jlong handle, jbyteArray plaintext) {
  util::java::ThrowingJniHelper jni_helper(env);
  ECCommutativeCipher* cipher;
  if (!AssignCipherOrThrow(env, handle, &cipher)) {
    return nullptr;
  }
  std::string plaintext_str = jni_helper.ByteArrayToString(plaintext);
  ::blinders::StatusOr<std::string> ciphertext = cipher->Encrypt(plaintext_str);
  if (!ciphertext.ok()) {
    ThrowIllegalArgumentException(&jni_helper, "Unable to encrypt: %s",
                                  ciphertext.status().ToString());
    return nullptr;
  }
  return jni_helper.StringToByteArray(*ciphertext).release();
}

extern "C" JNIEXPORT jbyteArray JNICALL
JFUN(reEncryptNative)(JNIEnv* env, jclass jni_class_ignored, jlong handle,
                      jbyteArray ciphertext) {
  util::java::ThrowingJniHelper jni_helper(env);
  ECCommutativeCipher* cipher;
  if (!AssignCipherOrThrow(env, handle, &cipher)) {
    return nullptr;
  }
  std::string ciphertext_str = jni_helper.ByteArrayToString(ciphertext);
  ::blinders::StatusOr<std::string> reencrypted_ciphertext =
      cipher->ReEncrypt(ciphertext_str);
  if (!reencrypted_ciphertext.ok()) {
    ThrowIllegalArgumentException(&jni_helper, "Unable to re-encrypt: %s",
                                  reencrypted_ciphertext.status().ToString());
    return nullptr;
  }
  return jni_helper.StringToByteArray(*reencrypted_ciphertext).release();
}

extern "C" JNIEXPORT jbyteArray JNICALL
JFUN(decryptNative)(JNIEnv* env, jclass jni_class_ignored, jlong handle,
                    jbyteArray ciphertext) {
  util::java::ThrowingJniHelper jni_helper(env);
  ECCommutativeCipher* cipher;
  if (!AssignCipherOrThrow(env, handle, &cipher)) {
    return nullptr;
  }
  std::string ciphertext_str = jni_helper.ByteArrayToString(ciphertext);
  ::blinders::StatusOr<std::string> plaintext = cipher->Decrypt(ciphertext_str);
  if (!plaintext.ok()) {
    ThrowIllegalArgumentException(&jni_helper, "Unable to decrypt: %s",
                                  plaintext.status().ToString());
    return nullptr;
  }
  return jni_helper.StringToByteArray(*plaintext).release();
}

extern "C" JNIEXPORT jbyteArray JNICALL JFUN(hashIntoTheCurveNative)(
    JNIEnv* env, jclass jni_class_ignored, jlong handle, jbyteArray byte_id) {
  util::java::ThrowingJniHelper jni_helper(env);
  ECCommutativeCipher* cipher;
  if (!AssignCipherOrThrow(env, handle, &cipher)) {
    return nullptr;
  }
  std::string byte_id_str = jni_helper.ByteArrayToString(byte_id);
  ::blinders::StatusOr<std::string> hash = cipher->HashToTheCurve(byte_id_str);
  if (!hash.ok()) {
    ThrowIllegalArgumentException(&jni_helper,
                                  "Unable to hash to the curve: %s",
                                  hash.status().ToString());
    return nullptr;
  }
  return jni_helper.StringToByteArray(*hash).release();
}

extern "C" JNIEXPORT jbyteArray JNICALL JFUN(getPrivateKeyBytesNative)(
    JNIEnv* env, jclass jni_class_ignored, jlong handle) {
  util::java::ThrowingJniHelper jni_helper(env);
  ECCommutativeCipher* cipher;
  if (!AssignCipherOrThrow(env, handle, &cipher)) {
    return nullptr;
  }
  return jni_helper.StringToByteArray(cipher->GetPrivateKeyBytes()).release();
}
