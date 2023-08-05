package com.linkedin.ktls;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;


/**
 * This class includes methods for SSL communication and the reference is taken from Apache Kafka's
 * <ul>
 *    <li>https://github.com/apache/kafka/blob/e0b7499103df9222140cdbf7047494d92913987e/clients/src/main/java/org/apache/kafka/common/network/SslTransportLayer.java#L841</li>
 * </ul>
 * TODO: LICENSE information to be added.
 */
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

  /**
   * Performs the WRAP function
   *
   * @return SSLEngineResult
   * @throws IOException
   */
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

  /**
   * Flushes the buffer to the network, non blocking.
   * Visible for testing.
   *
   * @param buf ByteBuffer
   * @return boolean true if the buffer has been emptied out, false otherwise
   * @throws IOException
   */
  private boolean flush(ByteBuffer buf) throws IOException {
    int remaining = buf.remaining();
    if (remaining > 0) {
      int written = channel.write(buf);
      return written >= remaining;
    }
    return true;
  }

  /**
   * This method is to read from socket channel to netReadBuffer.
   *
   * @return number of bytes read
   * @throws IOException
   */
  private int readFromChannel() throws IOException {
    return channel.read(netReadBuffer);
  }

  /**
   * This method is to perform handshake unwrap.
   *
   * @return SSLEngineResult
   * @throws IOException thrown in the cases of handshake failure.
   */
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

  /**
   * This method is to run SSLEngine tasks needed.
   *
   * @return HandshakeStatus
   */
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

  /**
   * This method is used to transfer contents from appReadBuffer to dst byte buffer.
   *
   * @param dst dst byte buffer
   * @return the number of bytes read
   */
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

  /**
   * Reads a sequence of bytes from this channel into the given buffer. Reads as much as possible
   * until there is no more data in the socket.
   *
   * @param dst The buffer into which bytes are to be transferred
   * @return The number of bytes read, possible zero or -1 if the channel has reached end-of-stream
   *         and no more data is available
   * @throws IOException if some other I/O error occurs
   */
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

  /**
   * Writes a sequence of bytes to this channel from the given buffer.
   *
   * @param src The buffer from which bytes are to be retrieved
   * @return The number of bytes read from src, possibly zero, or -1 if the channel has reached end-of-stream
   * @throws IOException If some other I/O error occurs
   */
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
