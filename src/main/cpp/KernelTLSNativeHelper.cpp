#include "jni_generated/com_linkedin_ktls_KernelTLSNativeHelper.h"

#include <cstring>
#include <cstdlib>
#include <string>

#ifdef __linux__
#  include <linux/version.h>
#  if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#    define NO_KTLS
#  else
#    include <sys/types.h>
#    include <sys/socket.h>
#    include <netinet/tcp.h>
#    include <linux/tls.h>
#  endif
#else
# define NO_KTLS
#endif

#define UNSUPPORTED_OS 6001
#define UNSUPPORTED_CIPHER 6002
#define UNSUPPORTED_OPERATION 6003
#define UNABLE_TO_SET_TLS_MODE 6004
#define UNABLE_TO_SET_TLS_PARAMS 6005

JNIEXPORT jint JNICALL Java_com_linkedin_ktls_KernelTLSNativeHelper_add(JNIEnv *env, jobject self, jint a, jint b) {
    return a + b;
}

#ifndef NO_KTLS
int startKernelTls(jint socketFd) {
    return setsockopt(socketFd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
}

int enableTlsWithCryptoInfo(int socketFd, bool sendingMode, void* crypto_info, unsigned int crypto_info_size) {
    int ret_code = startKernelTls(socketFd);
    if (ret_code != 0) {
        return UNABLE_TO_SET_TLS_MODE;
    }
    ret_code = setsockopt(socketFd, SOL_TLS, sendingMode ? TLS_TX : TLS_RX, crypto_info, crypto_info_size);
    if (ret_code != 0) {
        return UNABLE_TO_SET_TLS_PARAMS;
    }
    return 0;
}

void copyArray(JNIEnv *env, jbyteArray &src, unsigned char *dest) {
    jbyte* srcArr = env->GetByteArrayElements(src, NULL);
    jsize len = env->GetArrayLength(src);
    for (int idx = 0; idx < len; idx++) {
        dest[idx] = (unsigned char) srcArr[idx];
    }
    env->ReleaseByteArrayElements(src, srcArr, JNI_ABORT);
}
#endif

JNIEXPORT jint JNICALL Java_com_linkedin_ktls_KernelTLSNativeHelper_enableKernelTlsForSend_1AES_1128_1GCM(
    JNIEnv *env, jobject self, jint socketFd, jint versionCode,
    jbyteArray iv, jbyteArray key, jbyteArray salt, jbyteArray rec_seq) {
#ifdef NO_KTLS
    return UNSUPPORTED_OS;
#else
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    crypto_info.info.version = versionCode;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    copyArray(env, iv, crypto_info.iv);
    copyArray(env, key, crypto_info.key);
    copyArray(env, salt, crypto_info.salt);
    copyArray(env, rec_seq, crypto_info.rec_seq);
    return enableTlsWithCryptoInfo(socketFd, true, &crypto_info, sizeof(crypto_info));
#endif
}

JNIEXPORT jint JNICALL Java_com_linkedin_ktls_KernelTLSNativeHelper_enableKernelTlsForSend_1AES_1256_1GCM(
    JNIEnv *env, jobject self, jint socketFd, jint versionCode,
    jbyteArray iv, jbyteArray key, jbyteArray salt, jbyteArray rec_seq) {
#ifdef NO_KTLS
    return UNSUPPORTED_OS;
#else
    struct tls12_crypto_info_aes_gcm_256 crypto_info;
    crypto_info.info.version = versionCode;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
    copyArray(env, iv, crypto_info.iv);
    copyArray(env, key, crypto_info.key);
    copyArray(env, salt, crypto_info.salt);
    copyArray(env, rec_seq, crypto_info.rec_seq);
    return enableTlsWithCryptoInfo(socketFd, true, &crypto_info, sizeof(crypto_info));
#endif
}

JNIEXPORT jint JNICALL Java_com_linkedin_ktls_KernelTLSNativeHelper_enableKernelTlsForSend_1CHACHA20_1POLY1305(
    JNIEnv *env, jobject self, jint socketFd, jint versionCode,
    jbyteArray iv, jbyteArray key, jbyteArray salt, jbyteArray rec_seq) {
#ifdef NO_KTLS
    return UNSUPPORTED_OS;
#elif !defined TLS_CIPHER_CHACHA20_POLY1305
    return UNSUPPORTED_CIPHER;
#else
    struct tls12_crypto_info_chacha20_poly1305 crypto_info;
    crypto_info.info.version = versionCode;
    crypto_info.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
    copyArray(env, iv, crypto_info.iv);
    copyArray(env, key, crypto_info.key);
    copyArray(env, salt, crypto_info.salt);
    copyArray(env, rec_seq, crypto_info.rec_seq);
    return enableTlsWithCryptoInfo(socketFd, true, &crypto_info, sizeof(crypto_info));
#endif
}

JNIEXPORT jint JNICALL Java_com_linkedin_ktls_KTLS_disableKernelTls(
    JNIEnv *env, jobject self, jint socketFd) {
    return UNSUPPORTED_OPERATION;
}
