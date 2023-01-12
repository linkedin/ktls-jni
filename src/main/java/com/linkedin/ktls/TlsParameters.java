package com.linkedin.ktls;

class TlsParameters {
  final ProtocolVersion protocolVersion;
  final SymmetricCipher symmetricCipher;
  final byte[] iv;
  final byte[] key;
  final byte[] salt;
  final byte[] rec_seq;

  TlsParameters(ProtocolVersion protocolVersion, SymmetricCipher symmetricCipher,
      byte[] iv, byte[] key, byte[] salt, byte[] rec_seq) {
    this.protocolVersion = protocolVersion;
    this.symmetricCipher = symmetricCipher;
    this.iv = iv;
    this.key = key;
    this.salt = salt;
    this.rec_seq = rec_seq;
  }
}
