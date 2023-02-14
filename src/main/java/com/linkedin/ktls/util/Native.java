/*
 * This source file is modified from Luben's zstd-jni
 * https://github.com/luben/zstd-jni/blob/944df7a3ce4950ef800030810d3dc9488a397b4e/src/main/java/com/github/luben/zstd/util/Native.java
 *
 * And the below is the original license from the snapshot
 * ================================================================================
 * Zstd-jni: JNI bindings to Zstd Library
 *
 * Copyright (c) 2015-present, Luben Karavelov/ All rights reserved.
 *
 * BSD License
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.linkedin.ktls.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.UnsatisfiedLinkError;

public enum Native {
  ;

  private static final String libnameShort = "ktls-jni";
  private static final String libname = "lib" + libnameShort;
  private static final String errorMsg = "Unsupported OS/arch, cannot find " +
      resourceName() + " or load " + libnameShort + " from system libraries. Please " +
      "try building from source the jar or providing " + libname + " in your system.";

  private static String osName() {
    String os = System.getProperty("os.name").toLowerCase().replace(' ', '_');
    if (os.startsWith("win")){
      return "win";
    } else if (os.startsWith("mac")) {
      return "darwin";
    } else {
      return os;
    }
  }

  private static String libExtension() {
    if (osName().contains("os_x") || osName().contains("darwin")) {
      return "dylib";
    } else if (osName().contains("win")) {
      return "dll";
    } else {
      return "so";
    }
  }

  private static String resourceName() {
    return "/" + libname + "." + libExtension();
  }

  private static boolean loaded = false;

  public static synchronized void load() {
    load(null);
  }

  public static synchronized void load(final File tempFolder) {
    if (loaded) {
      return;
    }
    String resourceName = resourceName();

    // try to load the shared library directly from the JAR
    try {
      Class.forName("org.osgi.framework.BundleEvent"); // Simple OSGI env. check
      System.loadLibrary(libname);
      loaded = true;
      return;
    } catch (Throwable e) {
      // ignore both ClassNotFound and UnsatisfiedLinkError, and try other methods
    }

    InputStream is = Native.class.getResourceAsStream(resourceName);
    if (is == null) {
      // fall-back to loading the zstd-jni from the system library path.
      // It also cover loading on Android.
      try {
        System.loadLibrary(libnameShort);
        loaded = true;
        return;
      } catch (UnsatisfiedLinkError e) {
        UnsatisfiedLinkError err = new UnsatisfiedLinkError(e.getMessage() + "\n" + errorMsg);
        err.setStackTrace(e.getStackTrace());
        throw err;
      }
    }
    File tempLib = null;
    FileOutputStream out = null;
    try {
      tempLib = File.createTempFile(libname, "." + libExtension(), tempFolder);
      // try to delete on exit, does not work on Windows
      tempLib.deleteOnExit();
      // copy to tempLib
      out = new FileOutputStream(tempLib);
      byte[] buf = new byte[4096];
      while (true) {
        int read = is.read(buf);
        if (read == -1) {
          break;
        }
        out.write(buf, 0, read);
      }
      try {
        out.flush();
        out.close();
        out = null;
      } catch (IOException e) {
        // ignore
      }
      try {
        System.load(tempLib.getAbsolutePath());
      } catch (UnsatisfiedLinkError e) {
        // fall-back to loading the zstd-jni from the system library path
        try {
          System.loadLibrary(libnameShort);
        } catch (UnsatisfiedLinkError e1) {
          // display error in case problem with loading from temp folder
          // and from system library path - concatenate both messages
          UnsatisfiedLinkError err = new UnsatisfiedLinkError(
              e.getMessage() + "\n" +
                  e1.getMessage() + "\n"+
                  errorMsg);
          err.setStackTrace(e1.getStackTrace());
          throw err;
        }
      }
      loaded = true;
    } catch (IOException e) {
      // IO errors in extacting and writing the shared object in the temp dir
      ExceptionInInitializerError err = new ExceptionInInitializerError(
          "Cannot unpack " + libname + ": " + e.getMessage());
      err.setStackTrace(e.getStackTrace());
      throw err;
    } finally {
      try {
        is.close();
        if (out != null) {
          out.close();
        }
        if (tempLib != null && tempLib.exists()) {
          tempLib.delete();
        }
      } catch (IOException e) {
        // ignore
      }
    }
  }
}
