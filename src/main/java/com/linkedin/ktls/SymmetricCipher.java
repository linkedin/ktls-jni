package com.linkedin.ktls;

enum SymmetricCipher {
  AES_GCM_128("AES_GCM_128"),
  AES_GCM_256("AES_GCM_256"),
  CHACHA20_POLY1305("CHACHA20_POLY1305");

  final String cipherName;

  SymmetricCipher(String cipherName) {
    this.cipherName = cipherName;
  }
}
