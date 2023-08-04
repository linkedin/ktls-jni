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
 * data using AES-GCM encryption with TLSv1.3.
 */
public class TLS13AESGCMCipher implements TlsCipher {
  private static final byte[] APP_DATA_CONTENT_TYPE = new byte[]{23};
  private static final byte[] TLS_1_2_VERSION = new byte[]{3, 3};
  private static final int MAC_BYTES = 16;

  /**
   * This method encrypts the plain text using AES-GCM with TLS 1.3 parameters.
   *
   * @param plainText The plain text data to be encrypted.
   * @param tlsParameters The TLS parameters required for encryption (key, salt, and record sequence).
   * @return The encrypted data in the form of TLS record format.
   * @throws Exception
   */
  @Override
  public byte[] encrypt(final byte[] plainText, final TlsParameters tlsParameters) throws Exception {
    final byte[] nonce = getNonce(tlsParameters);

    final ByteArrayDataOutputStream innerPlainTextStream = new ByteArrayDataOutputStream();
    innerPlainTextStream.write(plainText);
    innerPlainTextStream.write(APP_DATA_CONTENT_TYPE);
    final byte[] innerPlainText = innerPlainTextStream.toByteArray();

    int cipherTextLength = innerPlainText.length + MAC_BYTES;
    final byte[] aadBytes = getAad(cipherTextLength);

    AEADParameters aeadParameters = new AEADParameters(
        new KeyParameter(tlsParameters.key), MAC_BYTES * 8, nonce, aadBytes);
    GCMBlockCipher gcmBlockCipher = new GCMBlockCipher(new AESEngine());
    gcmBlockCipher.init(true, aeadParameters);

    assertEquals(cipherTextLength, gcmBlockCipher.getOutputSize(innerPlainText.length));
    byte[] cipherText = new byte[cipherTextLength];
    int encLen = gcmBlockCipher.processBytes(innerPlainText, 0, innerPlainText.length, cipherText, 0);
    gcmBlockCipher.doFinal(cipherText, encLen);

    final ByteArrayDataOutputStream recordStream = new ByteArrayDataOutputStream();
    recordStream.write(APP_DATA_CONTENT_TYPE);
    recordStream.write(TLS_1_2_VERSION);
    recordStream.writeShort((short) (cipherTextLength));
    recordStream.write(cipherText);
    return recordStream.toByteArray();
  }

  /**
   * This method decrypts the TLS record data using AES-GCM with TLS 1.2 parameters.
   *
   * @param recordText The encrypted data in the form of TLS record format.
   * @param tlsParameters The TLS parameters required for decryption (key, salt, and record sequence).
   * @return The decrypted plain text data.
   * @throws Exception
   */
  @SuppressWarnings("unused") // Unused for now, but acts as good reference documentation
  public byte[] decrypt(byte[] recordText, TlsParameters tlsParameters) throws Exception {
    final ByteBuffer recordBuffer = ByteBuffer.allocate(recordText.length);
    recordBuffer.put(recordText);
    recordBuffer.flip();
    assertEquals(APP_DATA_CONTENT_TYPE[0], recordBuffer.get());
    assertEquals(TLS_1_2_VERSION[0], recordBuffer.get());
    assertEquals(TLS_1_2_VERSION[1], recordBuffer.get());
    final short cipherTextLength = recordBuffer.getShort();
    final byte[] cipherText = new byte[cipherTextLength];
    recordBuffer.get(cipherText);
    assertFalse(recordBuffer.hasRemaining());

    final byte[] nonce = getNonce(tlsParameters);

    final int innerPlainTextLength = cipherTextLength - MAC_BYTES;
    final byte[] aadBytes = getAad(cipherTextLength);

    AEADParameters aeadParameters = new AEADParameters(
        new KeyParameter(tlsParameters.key), MAC_BYTES * 8, nonce, aadBytes);
    GCMBlockCipher gcmBlockCipher = new GCMBlockCipher(new AESEngine());
    gcmBlockCipher.init(false, aeadParameters);

    assertEquals(innerPlainTextLength, gcmBlockCipher.getOutputSize(cipherText.length));
    byte[] innerPlainText = new byte[innerPlainTextLength];
    int decLen = gcmBlockCipher.processBytes(cipherText, 0, cipherText.length, innerPlainText, 0);
    gcmBlockCipher.doFinal(innerPlainText, decLen);

    int lastNonZeroIndex;
    for (lastNonZeroIndex = innerPlainTextLength - 1; lastNonZeroIndex >= 0; lastNonZeroIndex--) {
      if (innerPlainText[lastNonZeroIndex] != 0) {
        break;
      }
    }

    assertTrue(lastNonZeroIndex >= 0);
    assertEquals(APP_DATA_CONTENT_TYPE[0], innerPlainText[lastNonZeroIndex]);
    return Arrays.copyOf(innerPlainText, lastNonZeroIndex);
  }

  /**
   * This method generates the Additional Authentication Data (AAD) used in encryption/decryption.
   *
   * @param cipherTextLength The length of the cipher text data.
   * @return The AAD as a byte array.
   * @throws IOException
   */
  private byte[] getAad(int cipherTextLength) throws IOException {
    final ByteArrayDataOutputStream aadStream = new ByteArrayDataOutputStream();
    aadStream.write(APP_DATA_CONTENT_TYPE);
    aadStream.write(TLS_1_2_VERSION);
    aadStream.writeShort((short) cipherTextLength);
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
    final int ivLength = tlsParameters.iv.length;
    final int recSeqLength = tlsParameters.rec_seq.length;
    final byte[] nonce = Arrays.copyOf(tlsParameters.salt,
        saltLength + ivLength);
    System.arraycopy(tlsParameters.iv, 0,
        nonce, saltLength, ivLength);
    for (int i = 0; i < recSeqLength; i++) {
      nonce[saltLength + i] ^= tlsParameters.rec_seq[i];
    }
    return nonce;
  }
}
