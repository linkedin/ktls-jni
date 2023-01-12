package com.linkedin.ktls;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;


public class ServerSocketTest {
  @Test
  void test() throws Exception {
    final ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
    serverSocketChannel.configureBlocking(true);
    serverSocketChannel.bind(new InetSocketAddress(10532));
    final SocketChannel client = SocketChannel.open();
    client.configureBlocking(true);
    client.connect(new InetSocketAddress(10532));
    final SocketChannel server = serverSocketChannel.accept();

    ByteBuffer clientInBuffer = ByteBuffer.allocate(1024);
    ByteBuffer clientOutBuffer = ByteBuffer.allocate(1024);
    ByteBuffer serverInBuffer = ByteBuffer.allocate(1024);
    ByteBuffer serverOutBuffer = ByteBuffer.allocate(1024);

    verifyWrite("client_hello", client, server, clientOutBuffer, serverInBuffer);
    verifyWrite("server_hello", server, client, serverOutBuffer, clientInBuffer);
  }

  private void verifyWrite(String message, SocketChannel fromChannel, SocketChannel toChannel,
      ByteBuffer fromBuffer, ByteBuffer toBuffer) throws IOException {
    fromBuffer.clear();
    fromBuffer.put(message.getBytes(StandardCharsets.UTF_8));
    fromBuffer.flip();
    fromChannel.write(fromBuffer);

    toBuffer.clear();
    toChannel.read(toBuffer);
    toBuffer.flip();
    final String decodedMessage = StandardCharsets.UTF_8.decode(toBuffer).toString();
    assertEquals(decodedMessage, message);
  }
}
