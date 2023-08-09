package com.linkedin.ktls;

import java.util.Arrays;


/**
 * This is an enum class used to specify the TLS protocol version used in the library.
 */
enum ProtocolVersion {
  TLS_1_2("TLSv1.2", 0x0303), TLS_1_3("TLSv1.3", 0x0304);

  final String versionName;
  final int code;

  ProtocolVersion(final String versionName, final int code) {
    this.versionName = versionName;
    this.code = code;
  }

  static ProtocolVersion fromCode(int code) {
    return Arrays.stream(values()).filter(v -> v.code == code).findFirst().orElse(null);
  }
}
