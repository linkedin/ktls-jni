package com.linkedin.ktls;

import com.linkedin.ktls.util.Native;
import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.util.List;
import javax.net.ssl.SSLEngine;


/**
 * This class is a wrapper of KernelTLSNativeHelper and contains methods to invoke different methods present
 * in the native helper.
 */
public class KernelTls {
  static {
    Native.load();
  }

  private final TlsParametersExtractor extractor;
  private final KernelTLSNativeHelper kernelTLSNativeHelper = new KernelTLSNativeHelper();

  public KernelTls() {
    this(new TlsParametersExtractor());
  }

  KernelTls(TlsParametersExtractor extractor) {
    this.extractor = extractor;
  }

  /**
   * This method is used to call the KernelTLSNativeHelper enableKernelTlsForSend method
   * after extracting TlsParameters.
   *
   * @param engine SSLEngine object used to extract the TLSParameters
   * @param socketChannel SocketChannel object passed to KernelTLSNativeHelper
   * @throws KTLSEnableFailedException failed to enable ktls
   */
  public void enableKernelTlsForSend(SSLEngine engine, SocketChannel socketChannel) throws KTLSEnableFailedException {
    final TlsParameters tlsParameters = extractor.extract(engine);
    kernelTLSNativeHelper.enableKernelTlsForSend(socketChannel, tlsParameters);
  }

  /**
   * This method is a wrapper on top of the corresponding method in KernelTLSNativeHelper
   * to closeNotify a socket channel.
   *
   * @param socketChannel SocketChannel object
   * @throws IOException returned in cases of improper close notifying of the socket channel,
   * due to possible issues like broken pipe, etc.
   */
  public void closeNotify(SocketChannel socketChannel) throws IOException {
    kernelTLSNativeHelper.sendCloseNotify(socketChannel);
  }

  /**
   * This method is a wrapper for calling the kernelTLSNativeHelper to get supported cipher
   * suites.
   *
   * @return List of supported cipher strings
   */
  public List<String> supportedCipherSuites() {
    return kernelTLSNativeHelper.getSupportedCipherSuites();
  }
}
