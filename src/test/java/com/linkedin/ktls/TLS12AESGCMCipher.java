package com.linkedin.ktls;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This class implements the TlsCipher interface and provides methods to encrypt and decrypt
 * data using AES-GCM encryption with TLSv1.2
 */
public class TLS12AESGCMCipher implements TlsCipher {
  private static final byte[] APP_DATA_CONTENT_TYPE = new byte[]{23};
  private static final byte[] TLS_1_2_VERSION = new byte[]{3, 3};
  private static final int MAC_BYTES = 16;
  private static final int SEQ_NUM_BYTES = 8;

  /**
   * This method encrypts the plain text using AES-GCM with TLS 1.2 parameters.
   *
   * @param plainText The plain text data to be encrypted.
   * @param tlsParameters The TLS parameters required for encryption (key, salt, and record sequence).
   * @return The encrypted data in the form of TLS record format.
   */
  @Override
  public byte[] encrypt(final byte[] plainText, final TlsParameters tlsParameters) throws Exception {
    final byte[] nonce = getNonce(tlsParameters);
    final byte[] aadBytes = getAad(tlsParameters.rec_seq, plainText.length);

    AEADParameters aeadParameters = new AEADParameters(
        new KeyParameter(tlsParameters.key), MAC_BYTES * 8, nonce, aadBytes);
    GCMBlockCipher gcmBlockCipher = new GCMBlockCipher(new AESEngine());
    gcmBlockCipher.init(true, aeadParameters);

    byte[] cipherText = new byte[gcmBlockCipher.getOutputSize(plainText.length)];
    int encLen = gcmBlockCipher.processBytes(plainText, 0, plainText.length, cipherText, 0);
    gcmBlockCipher.doFinal(cipherText, encLen);

    final ByteArrayDataOutputStream recordStream = new ByteArrayDataOutputStream();
    recordStream.write(APP_DATA_CONTENT_TYPE);
    recordStream.write(TLS_1_2_VERSION);
    recordStream.writeShort((cipherText.length + tlsParameters.rec_seq.length));
    recordStream.write(tlsParameters.rec_seq);
    recordStream.write(cipherText);
    return recordStream.toByteArray();
  }

  /**
   * This method decrypts the TLS record data using AES-GCM with TLS 1.2 parameters.
   *
   * @param recordText The encrypted data in the form of TLS record format.
   * @param tlsParameters The TLS parameters required for decryption (key, salt, and record sequence).
   * @return The decrypted plain text data.
   */
  @SuppressWarnings("unused") // Unused for now, but acts as good reference documentation
  public byte[] decrypt(byte[] recordText, TlsParameters tlsParameters) throws Exception {
    final ByteBuffer recordBuffer = ByteBuffer.allocate(recordText.length);
    recordBuffer.put(recordText);
    recordBuffer.flip();
    assertEquals(APP_DATA_CONTENT_TYPE[0], recordBuffer.get());
    assertEquals(TLS_1_2_VERSION[0], recordBuffer.get());
    assertEquals(TLS_1_2_VERSION[1], recordBuffer.get());
    final short followingLength = recordBuffer.getShort();
    final byte[] recordSequence = new byte[SEQ_NUM_BYTES];
    recordBuffer.get(recordSequence);
    assertArrayEquals(tlsParameters.rec_seq, recordSequence);
    final int cipherTextLength = followingLength - recordSequence.length;
    final byte[] cipherText = new byte[cipherTextLength];
    recordBuffer.get(cipherText);
    assertFalse(recordBuffer.hasRemaining());

    final byte[] nonce = getNonce(tlsParameters);

    final int plainTextLength = cipherText.length - MAC_BYTES;
    final byte[] aadBytes = getAad(recordSequence, plainTextLength);

    AEADParameters aeadParameters = new AEADParameters(
        new KeyParameter(tlsParameters.key), MAC_BYTES * 8, nonce, aadBytes);
    GCMBlockCipher gcmBlockCipher = new GCMBlockCipher(new AESEngine());
    gcmBlockCipher.init(false, aeadParameters);

    assertEquals(plainTextLength, gcmBlockCipher.getOutputSize(cipherText.length));
    byte[] plainText = new byte[plainTextLength];
    int decLen = gcmBlockCipher.processBytes(cipherText, 0, cipherText.length, plainText, 0);
    gcmBlockCipher.doFinal(plainText, decLen);

    return plainText;
  }

  /**
   * This method generates the Additional Authentication Data (AAD) used in encryption/decryption.
   *
   * @param recordSequence The record sequence number.
   * @param plainTextLength The length of the plain text data.
   * @return The AAD as a byte array.
   */
  private byte[] getAad(byte[] recordSequence, int plainTextLength) throws IOException {
    final ByteArrayDataOutputStream aadStream = new ByteArrayDataOutputStream();
    aadStream.write(recordSequence);
    aadStream.write(APP_DATA_CONTENT_TYPE);
    aadStream.write(TLS_1_2_VERSION);
    aadStream.writeShort((short) plainTextLength);
    return aadStream.toByteArray();
  }

  /**
   * This method generates the nonce for AES-GCM encryption or decryption by combining the TLS salt and record sequence.
   *
   * @param tlsParameters The TLS parameters containing the salt and record sequence.
   * @return The nonce as a byte array.
   */
  private byte[] getNonce(TlsParameters tlsParameters) {
    final int saltLength = tlsParameters.salt.length;
    final int recSeqLength = tlsParameters.rec_seq.length;
    final byte[] nonce = Arrays.copyOf(tlsParameters.salt,
        saltLength + recSeqLength);
    System.arraycopy(tlsParameters.rec_seq, 0,
        nonce, saltLength, recSeqLength);
    return nonce;
  }
}
