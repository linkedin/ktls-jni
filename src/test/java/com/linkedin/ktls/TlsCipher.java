package com.linkedin.ktls;

public interface TlsCipher {
  byte[] encrypt(byte[] plainText, TlsParameters tlsParameters) throws Exception;
}
