package com.linkedin.ktls;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import static com.linkedin.ktls.CipherSuite.*;
import static org.junit.jupiter.api.Assertions.*;


public class KernelTlsTest extends KernelTLSTestBase {
  private static final KernelVersion MIN_SUPPORTED_KERNEL_VERSION = new KernelVersion("4.17");
  private static final KernelVersion MIN_SUPPORTED_KERNEL_VERSION_FOR_CHACHA20_POLY1305 = new KernelVersion("5.11");

  static class KernelVersion implements Comparable<KernelVersion> {
    private static final Pattern versionPattern = Pattern.compile("(\\d+).*\\.(\\d+).*");
    private final int major;
    private final int minor;
    KernelVersion(String version) {
      final Matcher matcher = versionPattern.matcher(version);
      final boolean matches = matcher.matches();
      assert matches;
      this.major = Integer.parseInt(matcher.group(1));
      this.minor = Integer.parseInt(matcher.group(1));
    }

    @Override
    public int compareTo(KernelVersion o) {
      return this.major < o.major ? -1 : this.minor - o.minor;
    }
  }

  private static boolean isLinux() {
    return System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("linux");
  }

  private static boolean isLinuxAndOlderThan(final KernelVersion version) {
    if (!isLinux()) {
      return false;
    }
    final KernelVersion currentVersion = new KernelVersion(System.getProperty("os.version"));
    return currentVersion.compareTo(version) < 0;
  }

  private static boolean isLinuxAndNotOlderThan(final KernelVersion version) {
    if (!isLinux()) {
      return false;
    }
    final KernelVersion currentVersion = new KernelVersion(System.getProperty("os.version"));
    return currentVersion.compareTo(version) >= 0;
  }

  @SuppressWarnings("unused") // Used by testKernelTlsSendFailsWithUnsupportedLinuxOS()
  private static boolean isUnsupportedLinuxVersion() {
    return isLinuxAndOlderThan(MIN_SUPPORTED_KERNEL_VERSION);
  }

  private static boolean isSupportedLinuxVersion() {
    return isLinuxAndNotOlderThan(MIN_SUPPORTED_KERNEL_VERSION);
  }

  @SuppressWarnings("unused")
  private static boolean isLinuxVersionTooOldForChaCha20Poly1305() {
    return isLinuxAndOlderThan(MIN_SUPPORTED_KERNEL_VERSION_FOR_CHACHA20_POLY1305);
  }

  @Test
  @EnabledOnOs({OS.LINUX})
  void testKernelTlsSendSucceeds() throws Exception {
    setupTlsHandshake(ProtocolVersion.TLS_1_2.versionName, TLS_RSA_WITH_AES_128_GCM_SHA256.suiteName);

    KernelTls kernelTls = new KernelTls();
    kernelTls.enableKernelTlsForSend(serverSSLEngine, serverChannel);

    byte[] serverPlainText = "server_hello1".getBytes(StandardCharsets.UTF_8);

    final ByteBuffer serverOutBuffer = ByteBuffer.allocate(1024);
    final ByteBuffer clientNetworkInBuffer = ByteBuffer.allocate(clientSSLEngine.getSession().getPacketBufferSize());
    final ByteBuffer clientAppInBuffer = ByteBuffer.allocate(clientSSLEngine.getSession().getApplicationBufferSize());

    serverOutBuffer.clear();
    serverOutBuffer.put(serverPlainText);
    serverOutBuffer.flip();
    serverChannel.write(serverOutBuffer);

    clientNetworkInBuffer.clear();
    clientChannel.read(clientNetworkInBuffer);
    clientNetworkInBuffer.flip();
    final byte[] clientNetworkInBytes = new byte[clientNetworkInBuffer.remaining()];
    clientNetworkInBuffer.get(clientNetworkInBytes);

    assertFalse(Arrays.equals(serverPlainText, clientNetworkInBytes));

    clientNetworkInBuffer.flip();

    final SSLEngineResult unwrap = clientSSLEngine.unwrap(clientNetworkInBuffer, clientAppInBuffer);
    assertEquals(SSLEngineResult.Status.OK, unwrap.getStatus());

    clientAppInBuffer.flip();
    final byte[] clientAppInBytes = new byte[clientAppInBuffer.remaining()];
    clientAppInBuffer.get(clientAppInBytes);

    assertArrayEquals(serverPlainText, clientAppInBytes);
  }

  @Test
  @EnabledOnOs({OS.MAC})
  void testKernelTlsSendFailsOnMacOS() throws Exception {
    setupTlsHandshake(ProtocolVersion.TLS_1_2.versionName, TLS_RSA_WITH_AES_128_GCM_SHA256.suiteName);

    KernelTls kernelTls = new KernelTls();
    assertThrows(KTLSEnableFailedException.class, () ->
        kernelTls.enableKernelTlsForSend(serverSSLEngine, serverChannel));
  }

  @Test
  @EnabledOnOs({OS.LINUX})
  void testKernelTlsSendFailsWithUnsupportedCipher() throws Exception {
    setupTlsHandshake(ProtocolVersion.TLS_1_2.versionName, "TLS_RSA_WITH_AES_256_CBC_SHA256");

    KernelTls kernelTls = new KernelTls();
    assertThrows(KTLSEnableFailedException.class, () ->
        kernelTls.enableKernelTlsForSend(serverSSLEngine, serverChannel));
  }

  @Test
  @EnabledIf("isUnsupportedLinuxVersion")
  void testKernelTlsSendFailsOnUnsupportedLinuxOS() throws Exception {
    setupTlsHandshake(ProtocolVersion.TLS_1_2.versionName, TLS_RSA_WITH_AES_128_GCM_SHA256.suiteName);

    KernelTls kernelTls = new KernelTls();
    assertThrows(KTLSEnableFailedException.class, () ->
        kernelTls.enableKernelTlsForSend(serverSSLEngine, serverChannel));
  }

  @Test
  @EnabledIf("isLinuxVersionTooOldForChaCha20Poly1305")
  void testKernelTlsSendFailsWithUnsupportedCipherOnLinuxVersion() throws Exception {
    setupTlsHandshake(ProtocolVersion.TLS_1_2.versionName, TLS_CHACHA20_POLY1305_SHA256.suiteName);

    KernelTls kernelTls = new KernelTls();
    assertThrows(KTLSEnableFailedException.class, () ->
        kernelTls.enableKernelTlsForSend(serverSSLEngine, serverChannel));
  }

  @Test
  @EnabledOnOs({OS.MAC})
  void testSupportedCipherSuitesIsEmptyOnUnsupportedOs() {
    KernelTls kernelTls = new KernelTls();
    assertTrue(kernelTls.supportedCipherSuites().isEmpty());
  }

  @Test
  @EnabledIf("isSupportedLinuxVersion")
  void testSupportedCipherSuitesIsNotEmpty() {
    KernelTls kernelTls = new KernelTls();
    final List<String> supportedCipherSuites = kernelTls.supportedCipherSuites();
    assertFalse(supportedCipherSuites.isEmpty());
    assertTrue(supportedCipherSuites.contains(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.suiteName));
  }
}
