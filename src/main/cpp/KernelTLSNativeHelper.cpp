#include "jni_generated/com_linkedin_ktls_KernelTLSNativeHelper.h"

#include <cstring>
#include <cstdlib>
#include <vector>

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
#  include <sys/socket.h>
#  define NO_KTLS
#endif

const char* AES_GCM_128_CIPHER_NAME = "AES_GCM_128";
const char* AES_GCM_256_CIPHER_NAME = "AES_GCM_256";
const char* CHACHA20_POLY1305_CIPHER_NAME = "CHACHA20_POLY1305";


/**
  * This method enables Kernel TLS for a specified socket by setting TCP_ULP to tls
  * This method is available only when NO_KTLS flag is not set
  * @param socketFd file descriptor on which kTLS has to be enabled.
*/
#ifndef NO_KTLS
int startKernelTls(jint socketFd) {

    return setsockopt(socketFd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
}

/**
 * This method is used to enable TLS for the specified socket using the provided crypto information.
 *
 * @param socketFd file descriptor of the socket to enable TLS.
 * @param sendingMode boolean indicating whether TLS is being enabled for sending or receiving
 * @param crypto_info pointer to the crypto information to be used for TLS.
 * @param crypto_info_size The size of the crypto information data structure
 * @return 0 on success, or an error code if enabling TLS fails
 */
int enableTlsWithCryptoInfo(int socketFd, bool sendingMode, void* crypto_info, unsigned int crypto_info_size) {
    int ret_code = startKernelTls(socketFd);
    if (ret_code != 0) {
        return com_linkedin_ktls_KernelTLSNativeHelper_UNABLE_TO_SET_TLS_MODE;
    }
    ret_code = setsockopt(socketFd, SOL_TLS, sendingMode ? TLS_TX : TLS_RX, crypto_info, crypto_info_size);
    if (ret_code != 0) {
        return com_linkedin_ktls_KernelTLSNativeHelper_UNABLE_TO_SET_TLS_PARAMS;
    }
    return 0;
}


/**
 * This method is used to copy data from a Java byte array to a C++ unsigned char buffer.
 *
 * @param env The JNI environment pointer
 * @param src source Java byte array to be copied
 * @param dest destination C++ unsigned char buffer to be copied
 * @param destSize size of the destination buffer to prevent buffer overruns.
 * @return The number of bytes copied on success, or -1 if the destination buffer is smaller than the source array.
 */
int copyArray(JNIEnv *env, jbyteArray &src, unsigned char *dest, size_t destSize) {
    jbyte* srcArr = env->GetByteArrayElements(src, NULL);
    jsize len = env->GetArrayLength(src);

    if (len > destSize) {
        env->ReleaseByteArrayElements(src, srcArr, JNI_ABORT);
        return -1;
    }

    memcpy(dest, reinterpret_cast<unsigned char*>(srcArr), len);
    env->ReleaseByteArrayElements(src, srcArr, JNI_ABORT);
    return len;
}
#endif


/**
 * This method is used to enable Kernel TLS for sending data using AES 128 GCM cipher.
 *
 * @param env The JNI environment pointer.
 * @param self reference to the Java KernelTLSNativeHelper object
 * @param socketFd file descriptor of the socket to enable TLS
 * @param versionCode The version code of the TLS protocol to use
 * @param iv the Initialization Vector for AES encryption
 * @param key the encryption key for AES encryption
 * @param salt the salt value for AES encryption
 * @param rec_seq the recent sequence number for AES encryption
 * @return 0 on success, or an error code indicating the specific failure reason.
 */
JNIEXPORT jint JNICALL Java_com_linkedin_ktls_KernelTLSNativeHelper_enableKernelTlsForSend_1AES_1128_1GCM(
    JNIEnv *env, jobject self, jint socketFd, jint versionCode,
    jbyteArray iv, jbyteArray key, jbyteArray salt, jbyteArray rec_seq) {
#ifdef NO_KTLS
    return com_linkedin_ktls_KernelTLSNativeHelper_UNSUPPORTED_OPERATING_SYSTEM;
#else
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    crypto_info.info.version = versionCode;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    int result_iv = copyArray(env, iv, crypto_info.iv, sizeof(crypto_info.iv));
    int result_key = copyArray(env, key, crypto_info.key, sizeof(crypto_info.key));
    int result_salt = copyArray(env, salt, crypto_info.salt, sizeof(crypto_info.salt));
    int result_rec_seq = copyArray(env, rec_seq, crypto_info.rec_seq, sizeof(crypto_info.rec_seq));
    if(result_iv == -1 || result_key == -1 || result_salt == -1 || result_rec_seq == -1)
      return com_linkedin_ktls_KernelTLSNativeHelper_BUFFER_OVERRUN;
    return enableTlsWithCryptoInfo(socketFd, true, &crypto_info, sizeof(crypto_info));
#endif
}

/**
 * This method is used to enable Kernel TLS for sending data using AES 256 GCM cipher.
 *
 * @param env The JNI environment pointer.
 * @param self reference to the Java KernelTLSNativeHelper object
 * @param socketFd file descriptor of the socket to enable TLS
 * @param versionCode The version code of the TLS protocol to use
 * @param iv the Initialization Vector for AES encryption
 * @param key the encryption key for AES encryption
 * @param salt the salt value for AES encryption
 * @param rec_seq the recent sequence number for AES encryption
 * @return 0 on success, or an error code indicating the specific failure reason.
 */
JNIEXPORT jint JNICALL Java_com_linkedin_ktls_KernelTLSNativeHelper_enableKernelTlsForSend_1AES_1256_1GCM(
    JNIEnv *env, jobject self, jint socketFd, jint versionCode,
    jbyteArray iv, jbyteArray key, jbyteArray salt, jbyteArray rec_seq) {
#ifdef NO_KTLS
    return com_linkedin_ktls_KernelTLSNativeHelper_UNSUPPORTED_OPERATING_SYSTEM;
#else
    struct tls12_crypto_info_aes_gcm_256 crypto_info;
    crypto_info.info.version = versionCode;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
    int result_iv = copyArray(env, iv, crypto_info.iv, sizeof(crypto_info.iv));
    int result_key = copyArray(env, key, crypto_info.key, sizeof(crypto_info.key));
    int result_salt = copyArray(env, salt, crypto_info.salt, sizeof(crypto_info.salt));
    int result_rec_seq = copyArray(env, rec_seq, crypto_info.rec_seq, sizeof(crypto_info.rec_seq));
    if(result_iv == -1 || result_key == -1 || result_salt == -1 || result_rec_seq == -1)
      return com_linkedin_ktls_KernelTLSNativeHelper_BUFFER_OVERRUN;
    return enableTlsWithCryptoInfo(socketFd, true, &crypto_info, sizeof(crypto_info));
#endif
}

/**
 * This method is used to enable Kernel TLS for sending data using CHACHA20_POLY1305 cipher.
 *
 * @param env The JNI environment pointer.
 * @param self reference to the Java KernelTLSNativeHelper object
 * @param socketFd file descriptor of the socket to enable TLS
 * @param versionCode The version code of the TLS protocol to use
 * @param iv the Initialization Vector for CHACHA20_POLY1305 encryption
 * @param key the encryption key for CHACHA20_POLY1305 encryption
 * @param salt the salt value for CHACHA20_POLY1305 encryption
 * @param rec_seq the recent sequence number for CHACHA20_POLY1305 encryption
 * @return 0 on success, or an error code indicating the specific failure reason.
 */
JNIEXPORT jint JNICALL Java_com_linkedin_ktls_KernelTLSNativeHelper_enableKernelTlsForSend_1CHACHA20_1POLY1305(
    JNIEnv *env, jobject self, jint socketFd, jint versionCode,
    jbyteArray iv, jbyteArray key, jbyteArray salt, jbyteArray rec_seq) {
#ifdef NO_KTLS
    return com_linkedin_ktls_KernelTLSNativeHelper_UNSUPPORTED_OPERATING_SYSTEM;
#else
    struct tls12_crypto_info_chacha20_poly1305 crypto_info;
    crypto_info.info.version = versionCode;
    crypto_info.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
    int result_iv = copyArray(env, iv, crypto_info.iv, sizeof(crypto_info.iv));
    int result_key = copyArray(env, key, crypto_info.key, sizeof(crypto_info.key));
    int result_salt = copyArray(env, salt, crypto_info.salt, sizeof(crypto_info.salt));
    int result_rec_seq = copyArray(env, rec_seq, crypto_info.rec_seq, sizeof(crypto_info.rec_seq));
    if(result_iv == -1 || result_key == -1 || result_salt == -1 || result_rec_seq == -1)
      return com_linkedin_ktls_KernelTLSNativeHelper_BUFFER_OVERRUN;
    return enableTlsWithCryptoInfo(socketFd, true, &crypto_info, sizeof(crypto_info));
#endif
}

/**
 * This method is a JNI method used to retrieve the list of supported symmetric ciphers for the native code.
 *
 * @param env The JNI environment pointer.
 * @param reference to the Java KernelTLSNativeHelper object
 * @return jobjectArray containing the strings of supported symmetric ciphers.
 */
JNIEXPORT jobjectArray JNICALL Java_com_linkedin_ktls_KernelTLSNativeHelper_getSupportedSymmetricCiphers
    (JNIEnv *env, jobject self) {
    jclass stringCls = env->FindClass("Ljava/lang/String;");
# ifdef NO_KTLS
    jobjectArray emptyArray = env->NewObjectArray(0, stringCls, NULL);
    return emptyArray;
# else
    std::vector<jstring> supportedCiphers;

    supportedCiphers.push_back(env->NewStringUTF(AES_GCM_128_CIPHER_NAME));
    supportedCiphers.push_back(env->NewStringUTF(AES_GCM_256_CIPHER_NAME));
# ifdef TLS_CIPHER_CHACHA20_POLY1305
    supportedCiphers.push_back(env->NewStringUTF(CHACHA20_POLY1305_CIPHER_NAME));
# endif
    jobjectArray resultArray = env->NewObjectArray(supportedCiphers.size(), stringCls, NULL);
    int index = 0;
    for (jstring cipherStr : supportedCiphers) {
        env->SetObjectArrayElement(resultArray, index++, cipherStr);
    }
    return resultArray;
#endif
}


/**
 * This method is a JNI method to send a control message over the TLS-enabled socket.
 *
 * @param env The JNI environment pointer
 * @param self reference to the Java KernelTLSNativeHelper object
 * @param socketFd file descriptor of the TLS-enabled socket.
 * @param recordType The record type to be set in the control message.
 * @param data The data to be sent along with the control message as a jbyteArray.
 * @return The result of the sendmsg function call, which indicates the number of bytes sent, or -1 if there was an error.
 */
JNIEXPORT jint JNICALL Java_com_linkedin_ktls_KernelTLSNativeHelper_sendControlMessage
  (JNIEnv *env, jobject self, jint socketFd, jbyte recordType, jbyteArray data) {
#ifdef NO_KTLS
    return -1;
#else
    jbyte* dataArr = env->GetByteArrayElements(data, NULL);
    jsize dataLen = env->GetArrayLength(data);

    msghdr msg = {0};
    // Record type is 1 byte
    int cmsg_len = 1;
    cmsghdr *cmsg;
    char buf[CMSG_SPACE(cmsg_len)];
    iovec msg_iov;   /* Vector of data to send/receive into.  */

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_TLS;
    cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
    cmsg->cmsg_len = CMSG_LEN(cmsg_len);
    *CMSG_DATA(cmsg) = recordType;
    msg.msg_controllen = cmsg->cmsg_len;

    msg_iov.iov_base = dataArr;
    msg_iov.iov_len = dataLen;
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    return sendmsg(socketFd, &msg, 0);
#endif
  }
