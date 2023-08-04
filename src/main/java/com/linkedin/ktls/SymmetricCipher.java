package com.linkedin.ktls;

/**
 * This is an enum class defining the list of symmetric ciphers that are allowed
 * for kernel TLS support to be enabled.
 */
enum SymmetricCipher {
  AES_GCM_128("AES_GCM_128"),
  AES_GCM_256("AES_GCM_256"),
  CHACHA20_POLY1305("CHACHA20_POLY1305");

  final String cipherName;

  SymmetricCipher(String cipherName) {
    this.cipherName = cipherName;
  }
}
