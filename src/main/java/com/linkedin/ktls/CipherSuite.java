package com.linkedin.ktls;

import java.util.Arrays;
import java.util.List;

import static com.linkedin.ktls.ProtocolVersion.*;
import static com.linkedin.ktls.SymmetricCipher.*;


enum CipherSuite {
  TLS_RSA_WITH_AES_128_GCM_SHA256("TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009C, AES_GCM_128, TLS_1_2),
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009E, AES_GCM_128, TLS_1_2),
  TLS_DHE_DSS_WITH_AES_128_GCM_SHA256("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 0x00A2, AES_GCM_128, TLS_1_2),
  TLS_DH_anon_WITH_AES_128_GCM_SHA256("TLS_DH_anon_WITH_AES_128_GCM_SHA256", 0x00A6, AES_GCM_128, TLS_1_2),
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02B, AES_GCM_128, TLS_1_2),
  TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02D, AES_GCM_128, TLS_1_2),
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC02F, AES_GCM_128, TLS_1_2),
  TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", 0xC031, AES_GCM_128, TLS_1_2),

  TLS_RSA_WITH_AES_256_GCM_SHA384("TLS_RSA_WITH_AES_256_GCM_SHA384", 0x009D, AES_GCM_256, TLS_1_2),
  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0x009F, AES_GCM_256, TLS_1_2),
  TLS_DHE_DSS_WITH_AES_256_GCM_SHA384("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 0x00A3, AES_GCM_256, TLS_1_2),
  TLS_DH_anon_WITH_AES_256_GCM_SHA384("TLS_DH_anon_WITH_AES_256_GCM_SHA384", 0x00A7, AES_GCM_256, TLS_1_2),
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xC02C, AES_GCM_256, TLS_1_2),
  TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", 0xC02E, AES_GCM_256, TLS_1_2),
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC030, AES_GCM_256, TLS_1_2),
  TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", 0xC032, AES_GCM_256, TLS_1_2),

  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA8,
      CHACHA20_POLY1305, TLS_1_2),
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9,
      CHACHA20_POLY1305, TLS_1_2),
  TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCAA,
      CHACHA20_POLY1305, TLS_1_2),

  TLS_AES_128_GCM_SHA256("TLS_AES_128_GCM_SHA256", 0x1301, AES_GCM_128, TLS_1_3),
  TLS_AES_256_GCM_SHA384("TLS_AES_256_GCM_SHA384", 0x1302, AES_GCM_256, TLS_1_3),
  TLS_CHACHA20_POLY1305_SHA256("TLS_CHACHA20_POLY1305_SHA256", 0x1303, CHACHA20_POLY1305, TLS_1_3);

  final String name;
  final int code;
  SymmetricCipher symmetricCipher;
  final List<ProtocolVersion> supportedVersions;

  CipherSuite(final String name, final int code, SymmetricCipher symmetricCipher, final ProtocolVersion... supportedVersions) {
    this.name = name;
    this.code = code;
    this.symmetricCipher = symmetricCipher;
    this.supportedVersions = Arrays.asList(supportedVersions);
  }

  static CipherSuite fromCode(int code) {
    return Arrays.stream(values()).filter(v -> v.code == code).findFirst().orElse(null);
  }
}
