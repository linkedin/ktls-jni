package com.linkedin.ktls;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import static org.junit.jupiter.api.Assertions.*;


public class TLS13AESGCMCipher implements TlsCipher {
  private static final byte[] APP_DATA_CONTENT_TYPE = new byte[]{23};
  private static final byte[] TLS_1_2_VERSION = new byte[]{3, 3};
  private static final int MAC_BYTES = 16;

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

  private byte[] getAad(int cipherTextLength) throws IOException {
    final ByteArrayDataOutputStream aadStream = new ByteArrayDataOutputStream();
    aadStream.write(APP_DATA_CONTENT_TYPE);
    aadStream.write(TLS_1_2_VERSION);
    aadStream.writeShort((short) cipherTextLength);
    return aadStream.toByteArray();
  }

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
