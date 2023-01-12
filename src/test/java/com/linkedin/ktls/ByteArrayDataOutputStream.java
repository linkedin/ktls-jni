package com.linkedin.ktls;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;


public class ByteArrayDataOutputStream extends DataOutputStream {
  private final ByteArrayOutputStream byteArrayOutputStream;
  private ByteArrayDataOutputStream(ByteArrayOutputStream byteArrayOutputStream) {
    super(byteArrayOutputStream);
    this.byteArrayOutputStream = byteArrayOutputStream;
  }

  public ByteArrayDataOutputStream() {
    this(new ByteArrayOutputStream());
  }

  public byte[] toByteArray() {
    return byteArrayOutputStream.toByteArray();
  }
}
