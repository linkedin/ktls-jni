package com.linkedin.ktls;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;


public class SslPeer {
  public static final ByteBuffer EMPTY_BUF = ByteBuffer.wrap(new byte[0]);

  private final String peerId;
  private final SSLEngine sslEngine;
  private final ByteChannel channel;
  private final ByteBuffer netReadBuffer;
  private final ByteBuffer netWriteBuffer;
  private final ByteBuffer appReadBuffer;
  private SSLEngineResult.HandshakeStatus handshakeStatus;
  private SSLEngineResult result;

  public SslPeer(
      String peerId, SSLEngine sslEngine,
      ByteChannel channel) {
    this.peerId = peerId;
    this.sslEngine = sslEngine;
    this.channel = channel;
    int appBufferSize = sslEngine.getSession().getApplicationBufferSize();
    int netBufferSize = sslEngine.getSession().getPacketBufferSize();
    netReadBuffer = ByteBuffer.allocate(netBufferSize);
    netWriteBuffer = ByteBuffer.allocate(netBufferSize);
    netReadBuffer.limit(0);
    netWriteBuffer.limit(0);
    appReadBuffer = ByteBuffer.allocate(appBufferSize);
  }

  public void doHandshake() throws IOException {
    result = null;
    handshakeStatus = sslEngine.getHandshakeStatus();
    int i = 0;
    while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
    handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
      switch (handshakeStatus) {
        case NEED_UNWRAP:
          result = handshakeUnwrap(); break;
        case NEED_WRAP:
          result = handshakeWrap(); break;
        case NEED_TASK:
          handshakeStatus = runDelegatedTasks(); break;
      }
    }
    netWriteBuffer.clear();
    netReadBuffer.clear();
    appReadBuffer.clear();
  }

  private SSLEngineResult handshakeWrap() throws IOException {
    if (netWriteBuffer.hasRemaining())
      throw new IllegalStateException("handshakeWrap called with netWriteBuffer not empty");
    //this should never be called with a network buffer that contains data
    //so we can clear it here.
    netWriteBuffer.clear();
    SSLEngineResult result = sslEngine.wrap(EMPTY_BUF, netWriteBuffer);
    //prepare the results to be written
    netWriteBuffer.flip();
    handshakeStatus = result.getHandshakeStatus();
    if (result.getStatus() == SSLEngineResult.Status.OK &&
        result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
      handshakeStatus = runDelegatedTasks();
    }

    flush(netWriteBuffer);
    return result;
  }

  private boolean flush(ByteBuffer buf) throws IOException {
    int remaining = buf.remaining();
    if (remaining > 0) {
      int written = channel.write(buf);
      return written >= remaining;
    }
    return true;
  }

  private int readFromChannel() throws IOException {
    return channel.read(netReadBuffer);
  }

  private SSLEngineResult handshakeUnwrap() throws IOException {
    int read = 0;
    if (result!= null && result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
      read = readFromChannel();
    }
    SSLEngineResult result;
    boolean cont;
    do {
      //prepare the buffer with the incoming data
      netReadBuffer.flip();
      result = sslEngine.unwrap(netReadBuffer, appReadBuffer);
      netReadBuffer.compact();
      handshakeStatus = result.getHandshakeStatus();
      if (result.getStatus() == SSLEngineResult.Status.OK &&
          result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
        handshakeStatus = runDelegatedTasks();
      }
      cont = result.getStatus() == SSLEngineResult.Status.OK &&
          handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
    } while (netReadBuffer.position() != 0 && cont);

    // Throw EOF exception for failed read after processing already received data
    // so that handshake failures are reported correctly
    if (read == -1)
      throw new EOFException("EOF during handshake, handshake status is " + handshakeStatus);

    return result;
  }

  private SSLEngineResult.HandshakeStatus runDelegatedTasks() {
    for (;;) {
      Runnable task = sslEngine.getDelegatedTask();
      if (task == null) {
        break;
      }
      task.run();
    }
    return sslEngine.getHandshakeStatus();
  }

  private int readFromAppBuffer(ByteBuffer dst) {
    appReadBuffer.flip();
    int remaining = Math.min(appReadBuffer.remaining(), dst.remaining());
    if (remaining > 0) {
      int limit = appReadBuffer.limit();
      appReadBuffer.limit(appReadBuffer.position() + remaining);
      dst.put(appReadBuffer);
      appReadBuffer.limit(limit);
    }
    appReadBuffer.compact();
    return remaining;
  }

  public int read(ByteBuffer dst) throws IOException {
    //if we have unread decrypted data in appReadBuffer read that into dst buffer.
    int read = 0;
    if (appReadBuffer.position() > 0) {
      read = readFromAppBuffer(dst);
    }

    // Each loop reads at most once from the socket.

    if (netReadBuffer.remaining() > 0) {
      readFromChannel();
    }

    while (netReadBuffer.position() > 0) {
      netReadBuffer.flip();
      SSLEngineResult unwrapResult;
      unwrapResult = sslEngine.unwrap(netReadBuffer, appReadBuffer);
      netReadBuffer.compact();
      // handle ssl renegotiation.
      if (unwrapResult.getStatus() == SSLEngineResult.Status.OK) {
        read += readFromAppBuffer(dst);
      } else {
        throw new IllegalStateException();
      }
    }
    return read;
  }

  public int write(ByteBuffer src) throws IOException {
    int written = 0;
    while (flush(netWriteBuffer) && src.hasRemaining()) {
      netWriteBuffer.clear();
      SSLEngineResult wrapResult = sslEngine.wrap(src, netWriteBuffer);
      netWriteBuffer.flip();

      if (wrapResult.getStatus() == SSLEngineResult.Status.OK) {
        written += wrapResult.bytesConsumed();
      } else {
        throw new IllegalStateException();
      }
    }
    return written;
  }

  @Override
  public String toString() {
    return "SslPeer{" + "peerId='" + peerId + '\'' + '}';
  }
}
