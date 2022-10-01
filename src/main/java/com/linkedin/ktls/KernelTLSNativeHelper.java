package com.linkedin.ktls;

import com.linkedin.ktls.util.Native;
import com.linkedin.ktls.util.ReflectionUtils;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


class KernelTLSNativeHelper {
  private static final int UNSUPPORTED_OPERATING_SYSTEM = 6001;
  private static final int UNSUPPORTED_CIPHER = 6002;
  private static final int UNSUPPORTED_OPERATION = 6003;
  private static final int UNABLE_TO_SET_TLS_MODE = 6004;
  private static final int UNABLE_TO_SET_TLS_PARAMS = 6005;

  static {
    Native.load();
  }

  int extractFd(SocketChannel socketChannel) throws KTLSEnableFailedException {
    try {
      final Object fileDescriptor =
          ReflectionUtils.getValueAtField("sun.nio.ch.SocketChannelImpl", "fd", socketChannel);
      return (int) ReflectionUtils.getValueAtField("java.io.FileDescriptor", "fd", fileDescriptor);
    } catch (Exception e) {
      throw new KTLSEnableFailedException("Error attempting to extract file descriptor from socket", e);
    }
  }

  void enableKernelTlsForSend(SocketChannel socketChannel, TlsParameters tlsParameters)
      throws KTLSEnableFailedException {
    final int fd = extractFd(socketChannel);
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
      throw buildExceptionForReturnCode(retCode);
    }
  }

  private KTLSEnableFailedException buildExceptionForReturnCode(int retCode) {
    switch (retCode) {
      case UNSUPPORTED_OPERATING_SYSTEM:
        return new KTLSEnableFailedException("ktls-jni was not built with support for this operating system");
      case UNSUPPORTED_CIPHER:
        return new KTLSEnableFailedException("ktls-jni was not built with support for the specified cipher");
      case UNSUPPORTED_OPERATION:
        return new KTLSEnableFailedException("This action is not supported.");
      case UNABLE_TO_SET_TLS_MODE:
        return new KTLSEnableFailedException("Unable to set socket to TLS mode. "
            + "This may indicate that the \"tls\" kernel module is not enabled.");
      case UNABLE_TO_SET_TLS_PARAMS:
        return new KTLSEnableFailedException("Unable to set TLS parameters on socket. "
            + "This is an unexpected scenario and needs further investigation.");
      default:
        return new KTLSEnableFailedException(String.format(
            "Unexpected error when trying to initialize Kernel TLS, return code %s", retCode));
    }
  }

  private native int enableKernelTlsForSend_AES_128_GCM(
      int fd, int version_code, byte[] iv, byte[] key, byte[] salt, byte[] rec_seq);
  private native int enableKernelTlsForSend_AES_256_GCM(
      int fd, int version_code, byte[] iv, byte[] key, byte[] salt, byte[] rec_seq);
  private native int enableKernelTlsForSend_CHACHA20_POLY1305(
      int fd, int version_code, byte[] iv, byte[] key, byte[] salt, byte[] rec_seq);

  public List<String> getSupportedCipherSuites() {
    final Set<String> supportedSymmetricCiphers = new HashSet<>(Arrays.asList(getSupportedSymmetricCiphers()));
    return Arrays.stream(CipherSuite.values())
        .filter(cs -> supportedSymmetricCiphers.contains(cs.symmetricCipher.cipherName))
        .map(cs -> cs.suiteName)
        .collect(Collectors.toList());
  }

  private native String[] getSupportedSymmetricCiphers();
}
