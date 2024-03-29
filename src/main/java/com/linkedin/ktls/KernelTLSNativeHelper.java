package com.linkedin.ktls;

import com.linkedin.ktls.util.Native;
import com.linkedin.ktls.util.ReflectionUtils;
import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * This class is a helper including utility methods to interact with the JNI code KernelTLSNativeHelper.cpp.
 * This class involves usage of reflection on JVM internals and therefore is fragile. The functionality of
 * this class has been tested on MSFT JDK 11 and linux kernel version 5.4.222, 5.15.111 and is likely
 * to break in a future version.
 */
class KernelTLSNativeHelper {
  private static final int UNSUPPORTED_OPERATING_SYSTEM = 6001;
  private static final int UNSUPPORTED_CIPHER = 6002;
  private static final int UNSUPPORTED_OPERATION = 6003;
  private static final int UNABLE_TO_SET_TLS_MODE = 6004;
  private static final int UNABLE_TO_SET_TLS_PARAMS = 6005;
  private static final int BUFFER_OVERRUN = 6006;

  private static final byte RECORD_TYPE_ALERT = 21;
  private static final byte ALERT_LEVEL_WARNING = 1;
  private static final byte ALERT_CLOSE_NOTIFY = 0;

  static {
    Native.load();
  }

  /**
   * Extracts the file descriptor associated with the given SocketChannel.
   * Note that this method is using Java reflection to extract the private field file
   * descriptor (fd) associated with a SocketChannel object and therefore is fragile.
   * It has been tested on MSFT JDK 11 and linux kernel version 5.4.222, 5.15.111.
   * This method relies on specific implementation details of the sun.nio.ch.SocketChannelImpl
   * class and the java.io.FileDescriptor class and these details vary in different JAVA versions.
   *
   * @param socketChannel The SocketChannel from which to extract the file descriptor.
   * @return The integer file descriptor associated with the SocketChannel.
   * @throws IllegalArgumentException If there is an error while extracting the file descriptor.
   */
  int extractFd(SocketChannel socketChannel) {
    try {
      final Object fileDescriptor =
          ReflectionUtils.getValueAtField("sun.nio.ch.SocketChannelImpl", "fd", socketChannel);
      return (int) ReflectionUtils.getValueAtField("java.io.FileDescriptor", "fd", fileDescriptor);
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * This function tries to enable kernelTLS for send based on the symmetric cipher value. The supported
   * symmetric ciphers are AES_GCM_128, AES_GCM_256 and CHACHA20_POLY1305.
   *
   * @param socketChannel SocketChannel object to enable kernelTLS on
   * @param tlsParameters TlsParameters with the symmetric cipher based on which we decide if kernel TLS can be enabled.
   * @throws KTLSEnableFailedException failed to enable ktls
   */
  void enableKernelTlsForSend(SocketChannel socketChannel, TlsParameters tlsParameters)
      throws KTLSEnableFailedException {
    final int fd;
    try {
      fd = extractFd(socketChannel);
    } catch (Exception e) {
      throw new KTLSEnableFailedException("Error attempting to extract file descriptor from socket", e);
    }
    final int retCode;
    switch (tlsParameters.symmetricCipher) {
      case AES_GCM_128:
        retCode = enableKernelTlsForSend_AES_128_GCM(fd, tlsParameters.protocolVersion.code,
            tlsParameters.iv, tlsParameters.key, tlsParameters.salt, tlsParameters.rec_seq);
        break;
      case AES_GCM_256:
        retCode = enableKernelTlsForSend_AES_256_GCM(fd, tlsParameters.protocolVersion.code,
            tlsParameters.iv, tlsParameters.key, tlsParameters.salt, tlsParameters.rec_seq);
        break;
      case CHACHA20_POLY1305:
        retCode = enableKernelTlsForSend_CHACHA20_POLY1305(fd, tlsParameters.protocolVersion.code,
            tlsParameters.iv, tlsParameters.key, tlsParameters.salt, tlsParameters.rec_seq);
        break;
      default:
        throw new IllegalStateException();
    }
    if (retCode != 0) {
      throw buildExceptionForReturnCode(retCode, tlsParameters.symmetricCipher);
    }
  }

  /**
   * This function is to throw the respective exception based on the return value from the underlying JNI kernel TLS enable call.
   * Also used OS version and symmetric cipher version for logging the exceptions.
   *
   * @param retCode Return value after performing kernel TLS enabled send
   * @param symmetricCipher Symmetric cipher used for logging in the exceptions.
   * @return KTLSEnableFailedException
   */
  private KTLSEnableFailedException buildExceptionForReturnCode(int retCode, SymmetricCipher symmetricCipher) {
    String osVersion = System.getProperty("os.version");
    switch (retCode) {
      case UNSUPPORTED_OPERATING_SYSTEM:
        return new KTLSEnableFailedException(
            "ktls-jni was not built with support for this operating system. os version: " + osVersion
                + ", symmetricCipher: " + symmetricCipher);
      case UNSUPPORTED_CIPHER:
        return new KTLSEnableFailedException(
            "ktls-jni was not built with support for the specified cipher. os version: " + osVersion
                + ", symmetricCipher: " + symmetricCipher);
      case UNSUPPORTED_OPERATION:
        return new KTLSEnableFailedException(
            "This action is not supported. os version: " + osVersion + ", symmetricCipher: " + symmetricCipher);
      case UNABLE_TO_SET_TLS_MODE:
        return new KTLSEnableFailedException("Unable to set socket to TLS mode. "
            + "This may indicate that the \"tls\" kernel module is not enabled on os version: " + osVersion
            + ", symmetricCipher: " + symmetricCipher);
      case UNABLE_TO_SET_TLS_PARAMS:
        return new KTLSEnableFailedException("Unable to set TLS parameters on socket. "
            + "This is an unexpected scenario and needs further investigation. os version: " + osVersion
            + ", symmetricCipher: " + symmetricCipher);
      case BUFFER_OVERRUN:
        return new KTLSEnableFailedException(
            "Found buffer overrun during copy array call. os version: " + osVersion + ", symmetricCipher: "
                + symmetricCipher);
      default:
        return new KTLSEnableFailedException(String.format(
            "Unexpected error when trying to initialize Kernel TLS, return code %s. os version : %s , symmetricCipher: %s",
            retCode, osVersion, symmetricCipher));
    }
  }

  private native int enableKernelTlsForSend_AES_128_GCM(
      int fd, int version_code, byte[] iv, byte[] key, byte[] salt, byte[] rec_seq);
  private native int enableKernelTlsForSend_AES_256_GCM(
      int fd, int version_code, byte[] iv, byte[] key, byte[] salt, byte[] rec_seq);
  private native int enableKernelTlsForSend_CHACHA20_POLY1305(
      int fd, int version_code, byte[] iv, byte[] key, byte[] salt, byte[] rec_seq);

  /**
   * This method is used to populate the supported symmetric ciphers using an ciphers array returned from NativeHelper.cpp.
   *
   * @return List<String> containing the cipher suites list.
   */
  public List<String> getSupportedCipherSuites() {
    final Set<String> supportedSymmetricCiphers = new HashSet<>(Arrays.asList(getSupportedSymmetricCiphers()));
    return Arrays.stream(CipherSuite.values())
        .filter(cs -> supportedSymmetricCiphers.contains(cs.symmetricCipher.cipherName))
        .map(cs -> cs.suiteName)
        .collect(Collectors.toList());
  }

  private native String[] getSupportedSymmetricCiphers();

  /**
   * This method is used to extract the file descriptor and send a close alert to the file descriptor.
   *
   * @param socketChannel SocketChannel object that is to be closed
   * @throws IOException thrown in the cases of failure in close notify of alert.
   */
  public void sendCloseNotify(SocketChannel socketChannel) throws IOException {
    final int socketFd = extractFd(socketChannel);
    final byte[] data = new byte[2];
    data[0] = ALERT_LEVEL_WARNING;
    data[1] = ALERT_CLOSE_NOTIFY;
    int result = sendControlMessage(socketFd, RECORD_TYPE_ALERT, data);
    if (result < 0) {
      throw new IOException("Failed to send close_notify alert");
    }
  }

  private native int sendControlMessage(int socketFd, byte recordType, byte[] data);
}
