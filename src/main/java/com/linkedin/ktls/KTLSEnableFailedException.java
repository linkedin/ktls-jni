package com.linkedin.ktls;

public class KTLSEnableFailedException extends Exception {
  KTLSEnableFailedException(String message) {
    super(message);
  }

  KTLSEnableFailedException(String message, Throwable cause) {
    super(message, cause);
  }

  KTLSEnableFailedException(Throwable cause) {
    super(cause);
  }
}
