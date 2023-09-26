# JNI implementation of EcCommutativeCipherNative methods.

load("//mobile/build:build_defs.bzl", "android_jni_library")

package(
    default_visibility = [
        "//java/com/google/privacy/blinders/encryption/commutative:__subpackages__",
        "//javatests/com/google/privacy/blinders/encryption/commutative:__subpackages__",
    ],
)

cc_library(
    name = "ec_commutative_cipher_native_jni",
    srcs = ["ec_commutative_cipher_native.cc"],
    deps = [
        "//privacy/blinders/cpp/crypto:bn_util",
        "//privacy/blinders/cpp/portable/util/task:status_includes",
        "//privacy/blinders/cpp/public:ec_commutative_cipher",
        "//privacy/private_membership/jni:jni_util",
        "//third_party/absl/status",
        "//third_party/absl/status:statusor",
        "//third_party/java/jdk:jni",  # build-cleaner: keep
        "//third_party/openssl:crypto",
        "//util/java:jni_helper",
        "//util/java:scoped_local_ref",
    ],
    alwayslink = 1,
)

android_jni_library(
    name = "ec_commutative_cipher_native_jni-android",
    deps = [
        ":ec_commutative_cipher_native_jni",
    ],
)
