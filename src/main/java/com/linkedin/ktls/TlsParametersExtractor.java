package com.linkedin.ktls;

import com.linkedin.ktls.util.ReflectionUtils;
import java.lang.reflect.InvocationTargetException;
import java.security.Key;
import java.util.Arrays;
import javax.net.ssl.SSLEngine;


class TlsParametersExtractor {

  private static final String SSL_PACKAGE_PREFIX = "sun.security.ssl.";
  private static final int GCM_SALT_SIZE = 4;
  private static final int GCM_IV_SIZE = 8;
  private static final int SEQ_NUMBER_SIZE = 8;

  public TlsParameters extract(SSLEngine sslEngine) throws KTLSEnableFailedException {
    try {
      ReflectionUtils.getValueAtField(getSslClass("SSLEngineImpl"), "conContext", sslEngine);
      return extractForJdkWithTLS1_3Support(sslEngine);
    } catch (NoSuchFieldException e) {
      return extractForJdkWithoutTLS1_3Support(sslEngine);
    } catch (Exception e) {
      throw new KTLSEnableFailedException(
          "Error in getting TLS parameters from SSLEngine; Java version not supported", e);
    }
  }

  private TlsParameters extractForJdkWithoutTLS1_3Support(SSLEngine sslEngine) throws KTLSEnableFailedException {
    try {
      final Object sslSession = ReflectionUtils.getValueAtField(getSslClass("SSLEngineImpl"), "sess", sslEngine);
      final Object protocolVersionInternal =
          ReflectionUtils.getValueAtField(getSslClass("SSLSessionImpl"), "protocolVersion", sslSession);
      final int protocolId =
          (int) ReflectionUtils.getValueAtField(getSslClass("ProtocolVersion"), "v", protocolVersionInternal);

      final Object cipherSuiteInternal =
          ReflectionUtils.getValueAtField(getSslClass("SSLSessionImpl"), "cipherSuite", sslSession);
      final int cipherSuiteId =
          (int) ReflectionUtils.getValueAtField(getSslClass("CipherSuite"), "id", cipherSuiteInternal);

      ProtocolVersion protocolVersion = ProtocolVersion.fromCode(protocolId);
      CipherSuite cipherSuite = CipherSuite.fromCode(cipherSuiteId);

      if (isCipherSuiteUnsupported(protocolVersion, cipherSuite)) {
        throw new KTLSEnableFailedException(String.format(
            "Cipher suite %s with protocol %s is not supported for kernel TLS.", cipherSuiteId, protocolId));
      }

      final Object authenticator =
          ReflectionUtils.getValueAtField(getSslClass("SSLEngineImpl"), "writeAuthenticator", sslEngine);
      final Object cipherBox =
          ReflectionUtils.getValueAtField(getSslClass("SSLEngineImpl"), "writeCipher", sslEngine);
      return extractParametersV1AES_GCM(protocolVersion, cipherSuite, cipherBox, authenticator);
    } catch (Exception e) {
      throw new KTLSEnableFailedException("Error during using reflection to get TLS parameters from SSLEngine", e);
    }
  }

  private TlsParameters extractForJdkWithTLS1_3Support(SSLEngine sslEngine) throws KTLSEnableFailedException {
    try {
      final Object transportContext =
          ReflectionUtils.getValueAtField(getSslClass("SSLEngineImpl"), "conContext", sslEngine);
      final Object sslSession =
          ReflectionUtils.getValueAtField(getSslClass("TransportContext"), "conSession", transportContext);

      final Object protocolVersionInternal =
          ReflectionUtils.getValueAtField(getSslClass("SSLSessionImpl"), "protocolVersion", sslSession);
      final int protocolId =
          (int) ReflectionUtils.getValueAtField(getSslClass("ProtocolVersion"), "id", protocolVersionInternal);

      final Object cipherSuiteInternal =
          ReflectionUtils.getValueAtField(getSslClass("SSLSessionImpl"), "cipherSuite", sslSession);
      final int cipherSuiteId =
          (int) ReflectionUtils.getValueAtField(getSslClass("CipherSuite"), "id", cipherSuiteInternal);

      ProtocolVersion protocolVersion = ProtocolVersion.fromCode(protocolId);
      CipherSuite cipherSuite = CipherSuite.fromCode(cipherSuiteId);

      if (isCipherSuiteUnsupported(protocolVersion, cipherSuite)) {
        throw new KTLSEnableFailedException(String.format("Cipher suite %s with protocol %s is not supported for kernel TLS.", cipherSuiteId, protocolId));
      }
      final Object outputRecord =
          ReflectionUtils.getValueAtField(getSslClass("TransportContext"), "outputRecord", transportContext);
      final Object writeCipher =
          ReflectionUtils.getValueAtField(getSslClass("OutputRecord"), "writeCipher", outputRecord);
      final V2Extractor v2Extractor = buildV2Extractor(protocolVersion, cipherSuite);
      return v2Extractor.extract(writeCipher);
    } catch (Exception e) {
      throw new KTLSEnableFailedException("Error during using reflection to get TLS parameters from SSLEngine", e);
    }
  }

  private boolean isCipherSuiteUnsupported(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
    if (protocolVersion == null || cipherSuite == null) {
      return true;
    }
    return !cipherSuite.supportedVersions.contains(protocolVersion);
  }

  private TlsParameters extractParametersV1AES_GCM(
      ProtocolVersion protocolVersion, CipherSuite cipherSuite,
      Object cipherBox, Object authenticator) throws Exception {
    if (cipherSuite.symmetricCipher != SymmetricCipher.AES_GCM_128
        && cipherSuite.symmetricCipher != SymmetricCipher.AES_GCM_256) {
      throw new IllegalStateException("Invalid cipherSuiteId");
    }
    byte[] salt = (byte[]) ReflectionUtils.getValueAtField(
        getSslClass("CipherBox"), "fixedIv", cipherBox);
    assert salt.length == GCM_SALT_SIZE;

    Key writeSecret = (Key) ReflectionUtils.getValueAtField(
        getSslClass("CipherBox"), "key", cipherBox);
    byte[] key = writeSecret.getEncoded();

    byte[] sequenceNumber = (byte[]) ReflectionUtils.getValueAtMethod(
        getSslClass("Authenticator"), "sequenceNumber", authenticator);
    assert sequenceNumber.length == SEQ_NUMBER_SIZE;

    return new TlsParameters(
        protocolVersion, cipherSuite.symmetricCipher, new byte[GCM_IV_SIZE], key, salt, sequenceNumber);
  }

  private V2Extractor buildV2Extractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
    if (protocolVersion == ProtocolVersion.TLS_1_2) {
      if (cipherSuite.symmetricCipher == SymmetricCipher.AES_GCM_128) {
        return new TLS12Aes128GcmExtractor(protocolVersion, cipherSuite);
      } else if (cipherSuite.symmetricCipher == SymmetricCipher.AES_GCM_256) {
        return new TLS12Aes256GcmExtractor(protocolVersion, cipherSuite);
      } else if (cipherSuite.symmetricCipher == SymmetricCipher.CHACHA20_POLY1305) {
        return new TLS12CC20P1305Extractor(protocolVersion, cipherSuite);
      }
    } else if (protocolVersion == ProtocolVersion.TLS_1_3) {
      if (cipherSuite.symmetricCipher == SymmetricCipher.AES_GCM_128) {
        return new TLS13Aes128GcmExtractor(protocolVersion, cipherSuite);
      } else if (cipherSuite.symmetricCipher == SymmetricCipher.AES_GCM_256) {
        return new TLS13Aes256GcmExtractor(protocolVersion, cipherSuite);
      } else if (cipherSuite.symmetricCipher == SymmetricCipher.CHACHA20_POLY1305) {
        return new TLS13CC20P1305Extractor(protocolVersion, cipherSuite);
      }
    }
    throw new IllegalStateException("Invalid protocolId and cipherSuiteId");
  }

  private static String getSslClass(final String classSimpleName) {
    return SSL_PACKAGE_PREFIX + classSimpleName;
  }

  interface V2Extractor {
    default byte[] extractSequenceNumber(Object writeCipher)
        throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException,
               NoSuchFieldException {
      Object authenticator = ReflectionUtils.getValueAtField(
          getSslClass("SSLCipher$SSLWriteCipher"), "authenticator", writeCipher);
      return (byte[]) ReflectionUtils.getValueAtMethod(
          getSslClass("Authenticator"), "sequenceNumber", authenticator);
    }

    TlsParameters extract(Object writeCipher)
        throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException, InvocationTargetException,
               NoSuchMethodException;
  }

  private static abstract class TLS12GcmExtractor implements V2Extractor {
    private final int keySize;
    private final ProtocolVersion protocolVersion;
    private final CipherSuite cipherSuite;

    public TLS12GcmExtractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite, int keySize) {
      this.protocolVersion = protocolVersion;
      this.cipherSuite = cipherSuite;
      this.keySize = keySize;
    }

    @Override
    public TlsParameters extract(Object writeCipher)
        throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException, InvocationTargetException,
               NoSuchMethodException {
      byte[] salt = (byte[]) ReflectionUtils.getValueAtField(
          getSslClass("SSLCipher$T12GcmWriteCipherGenerator$GcmWriteCipher"), "fixedIv", writeCipher);
      assert salt.length == GCM_SALT_SIZE;

      Key writeSecret = (Key) ReflectionUtils.getValueAtField(
          getSslClass("SSLCipher$T12GcmWriteCipherGenerator$GcmWriteCipher"), "key", writeCipher);
      byte[] key = writeSecret.getEncoded();
      assert key.length == keySize;

      byte[] sequenceNumber = extractSequenceNumber(writeCipher);
      assert sequenceNumber.length == SEQ_NUMBER_SIZE;

      return new TlsParameters(
          protocolVersion, cipherSuite.symmetricCipher, new byte[GCM_IV_SIZE], key, salt, sequenceNumber);
    }
  }

  private static class TLS12Aes128GcmExtractor extends TLS12GcmExtractor {
    private static final int KEY_SIZE = 16;
    public TLS12Aes128GcmExtractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
      super(protocolVersion, cipherSuite, KEY_SIZE);
    }
  }

  private static class TLS12Aes256GcmExtractor extends TLS12GcmExtractor {
    private static final int KEY_SIZE = 32;
    public TLS12Aes256GcmExtractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
      super(protocolVersion, cipherSuite, KEY_SIZE);
    }
  }

  private static abstract class TLS13GcmExtractor implements V2Extractor {
    private final int keySize;
    private final ProtocolVersion protocolVersion;
    private final CipherSuite cipherSuite;

    public TLS13GcmExtractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite, int keySize) {
      this.protocolVersion = protocolVersion;
      this.cipherSuite = cipherSuite;
      this.keySize = keySize;
    }

    @Override
    public TlsParameters extract(Object writeCipher)
        throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException, InvocationTargetException,
               NoSuchMethodException {
      byte[] fullIv = (byte[]) ReflectionUtils.getValueAtField(
          getSslClass("SSLCipher$T13GcmWriteCipherGenerator$GcmWriteCipher"), "iv", writeCipher);
      assert fullIv.length == GCM_SALT_SIZE + GCM_IV_SIZE;
      byte[] salt = Arrays.copyOf(fullIv, GCM_SALT_SIZE);
      byte[] iv = new byte[GCM_IV_SIZE];
      System.arraycopy(fullIv, GCM_SALT_SIZE, iv, 0, GCM_IV_SIZE);

      Key writeSecret = (Key) ReflectionUtils.getValueAtField(
          getSslClass("SSLCipher$T13GcmWriteCipherGenerator$GcmWriteCipher"), "key", writeCipher);
      byte[] key = writeSecret.getEncoded();
      assert key.length == keySize;

      byte[] sequenceNumber = extractSequenceNumber(writeCipher);
      assert sequenceNumber.length == SEQ_NUMBER_SIZE;

      return new TlsParameters(protocolVersion, cipherSuite.symmetricCipher, iv, key, salt, sequenceNumber);
    }
  }

  private static class TLS13Aes128GcmExtractor extends TLS13GcmExtractor {
    private static final int KEY_SIZE = 16;
    public TLS13Aes128GcmExtractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
      super(protocolVersion, cipherSuite, KEY_SIZE);
    }
  }

  private static class TLS13Aes256GcmExtractor extends TLS13GcmExtractor {
    private static final int KEY_SIZE = 32;
    public TLS13Aes256GcmExtractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
      super(protocolVersion, cipherSuite, KEY_SIZE);
    }
  }

  private static abstract class CC20P1305Extractor implements V2Extractor {
    private static final int SALT_SIZE = 0;
    private static final int IV_SIZE = 12;
    private static final int KEY_SIZE = 32;

    private final ProtocolVersion protocolVersion;
    private final CipherSuite cipherSuite;
    private final String writeCipherClassName;

    public CC20P1305Extractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite, String writeCipherClassName) {
      this.protocolVersion = protocolVersion;
      this.cipherSuite = cipherSuite;
      this.writeCipherClassName = writeCipherClassName;
    }

    @Override
    public TlsParameters extract(Object writeCipher)
        throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException, InvocationTargetException,
               NoSuchMethodException {
      byte[] fullIv = (byte[]) ReflectionUtils.getValueAtField(writeCipherClassName, "iv", writeCipher);
      assert fullIv.length == SALT_SIZE + IV_SIZE;
      byte[] salt = Arrays.copyOf(fullIv, SALT_SIZE);
      byte[] iv = new byte[IV_SIZE];
      System.arraycopy(fullIv, SALT_SIZE, iv, 0, IV_SIZE);

      Key writeSecret = (Key) ReflectionUtils.getValueAtField(writeCipherClassName, "key", writeCipher);
      byte[] key = writeSecret.getEncoded();
      assert key.length == KEY_SIZE;

      byte[] sequenceNumber = extractSequenceNumber(writeCipher);
      assert sequenceNumber.length == SEQ_NUMBER_SIZE;

      return new TlsParameters(protocolVersion, cipherSuite.symmetricCipher, iv, key, salt, sequenceNumber);
    }
  }

  private static class TLS12CC20P1305Extractor extends CC20P1305Extractor {
    public TLS12CC20P1305Extractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
      super(protocolVersion, cipherSuite,
          getSslClass("SSLCipher$T12CC20P1305WriteCipherGenerator$CC20P1305WriteCipher"));
    }
  }

  private static class TLS13CC20P1305Extractor extends CC20P1305Extractor {
    public TLS13CC20P1305Extractor(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
      super(protocolVersion, cipherSuite,
          getSslClass("SSLCipher$T13CC20P1305WriteCipherGenerator$CC20P1305WriteCipher"));
    }
  }
}
