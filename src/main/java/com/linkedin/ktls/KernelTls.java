package com.linkedin.ktls;

import com.linkedin.ktls.util.Native;
import java.nio.channels.SocketChannel;
import java.util.List;
import javax.net.ssl.SSLEngine;


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

  public void enableKernelTlsForSend(SSLEngine engine, SocketChannel socketChannel) throws KTLSEnableFailedException {
    final TlsParameters tlsParameters = extractor.extract(engine);
    kernelTLSNativeHelper.enableKernelTlsForSend(socketChannel, tlsParameters);
  }

  public List<String> supportedCipherSuites() {
    return kernelTLSNativeHelper.getSupportedCipherSuites();
  }
}
