package com.linkedin.ktls;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static com.linkedin.ktls.CipherSuite.*;
import static com.linkedin.ktls.ProtocolVersion.*;
import static org.junit.jupiter.api.Assertions.*;


/**
 *  This test class includes validation end-to-end tests to check TlsParameter extraction by encrypt-decrypt testing
 *  of plain text messages based on Tls protocol version and cipher suite version.
 */
public class TlsParametersV2ExtractorTest extends KernelTLSTestBase {
  private static final int MIN_PLAINTEXT_SIZE = 256;
  private static final int MAX_PLAINTEXT_SIZE = 512;
  private static final int DECRYPTION_BUFFER_SIZE = 1024 * 10;

  @SuppressWarnings("unused") // This method is used by Junit for generating test parameters
  private static Stream<Arguments> validateEncryptedRecordArgProviderTls1_2() {
    return Stream.of(
        Arguments.of(
            TLS_1_2,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            new TLS12AESGCMCipher()),
        Arguments.of(
            TLS_1_2,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            new TLS12AESGCMCipher()));
  }

  @SuppressWarnings("unused") // This method is used by Junit for generating test parameters
  private static Stream<Arguments> validateEncryptedRecordArgProviderTls1_3() {
    return Stream.of(
        Arguments.of(
            TLS_1_3,
            TLS_AES_256_GCM_SHA384,
            new TLS13AESGCMCipher()),
        Arguments.of(
            TLS_1_3,
            TLS_AES_128_GCM_SHA256,
            new TLS13AESGCMCipher()));
  }

  @ParameterizedTest
  @MethodSource("validateEncryptedRecordArgProviderTls1_3")
  @EnabledForJreRange(min = JRE.JAVA_11)
  void validate_decrypted_record_tls1_3(
      ProtocolVersion tlsProtocolVersion, CipherSuite cipherSuite, TlsCipher tlsCipher) throws Exception {
    validate_decrypted_record(tlsProtocolVersion, cipherSuite, tlsCipher);
  }

  @ParameterizedTest
  @MethodSource("validateEncryptedRecordArgProviderTls1_2")
  void validate_decrypted_record_tls1_2(
      ProtocolVersion tlsProtocolVersion, CipherSuite cipherSuite, TlsCipher tlsCipher) throws Exception {
    validate_decrypted_record(tlsProtocolVersion, cipherSuite, tlsCipher);
  }

  /**
   * This is a test method to validate the decryption of a record using TLS. This includes setting up
   * the TLS handshake, generating random plain text of variable size for encryption testing, encrypt the generated
   * plain text using the specified TLS cipher and parameters, attempt to decrypt the encrypted record using the
   * server-side SSL engine and verifying with the original plain text message.
   *
   * @param tlsProtocolVersion ProtocolVersion
   * @param cipherSuite CipherSuite
   * @param tlsCipher TlsCipher
   * @throws Exception thrown as a general exception in cases validation failures.
   */
  void validate_decrypted_record(
      ProtocolVersion tlsProtocolVersion, CipherSuite cipherSuite, TlsCipher tlsCipher) throws Exception {
    setupTlsHandshake(tlsProtocolVersion.versionName, cipherSuite.suiteName);

    final TlsParametersExtractor extractor = new TlsParametersExtractor();
    final TlsParameters tlsParameters = extractor.extract(clientSSLEngine);

    Random random = new Random(System.currentTimeMillis());
    final int plainTextSize = MIN_PLAINTEXT_SIZE + random.nextInt(MAX_PLAINTEXT_SIZE - MIN_PLAINTEXT_SIZE + 1);
    byte[] plainText = new byte[plainTextSize];
    random.nextBytes(plainText);

    final byte[] encryptedRecord = tlsCipher.encrypt(plainText, tlsParameters);

    ByteBuffer encryptedBuffer = ByteBuffer.wrap(encryptedRecord);
    ByteBuffer decryptedBuffer = ByteBuffer.allocate(DECRYPTION_BUFFER_SIZE);
    serverSSLEngine.unwrap(encryptedBuffer, decryptedBuffer);

    decryptedBuffer.flip();
    byte[] decryptedPlainText = new byte[decryptedBuffer.remaining()];
    decryptedBuffer.get(decryptedPlainText);

    assertArrayEquals(plainText, decryptedPlainText);
  }

  private String toHex(byte[] arr) {
    return new String(Hex.encode(arr), StandardCharsets.UTF_8);
  }

  @SuppressWarnings("unused")
  private String toPrettyString(TlsParameters params) {
    return "TlsParameters{"
        + "protocolVersion=" + params.protocolVersion
        + ", symmetricCipher=" + params.symmetricCipher
        + ", iv=" + toHex(params.iv)
        + ", key=" + toHex(params.key)
        + ", salt=" + toHex(params.salt)
        + ", rec_seq=" + toHex(params.rec_seq)
        + '}';
  }
}
