package com.linkedin.ktls;

import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLEngine;
import org.junit.jupiter.api.BeforeEach;


/**
 * This is a base test class and define setupTlsHandshake method for subclasses. This defines
 * sslEngine for server and client and also SocketChannel objects to be used by several other tests.
 */
public class KernelTLSTestBase {
  protected static final AtomicInteger portNumber = new AtomicInteger(9320);

  protected SSLEngine serverSSLEngine;
  protected SSLEngine clientSSLEngine;
  protected SslPeer server;
  protected SslPeer client;
  protected SocketChannel clientChannel;
  protected SocketChannel serverChannel;

  protected void setupTlsHandshake(String protocolVersion, String cipherSuite) throws Exception {
    portNumber.incrementAndGet();
    SslEngineGenerator sslEngineGenerator = new SslEngineGenerator(
        protocolVersion, cipherSuite);
    serverSSLEngine = sslEngineGenerator.getServerSSLEngine();
    clientSSLEngine = sslEngineGenerator.getClientSSLEngine();

    final ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
    serverSocketChannel.configureBlocking(true);
    int port = portNumber.get();
    serverSocketChannel.bind(new InetSocketAddress(port));
    clientChannel = SocketChannel.open();
    clientChannel.configureBlocking(true);
    clientChannel.connect(new InetSocketAddress(port));
    serverChannel = serverSocketChannel.accept();
    serverChannel.configureBlocking(true);

    final String serverName = String.format("%s-server", getClass().getSimpleName());
    final String clientName = String.format("%s-client", getClass().getSimpleName());
    server = new SslPeer(serverName, serverSSLEngine, serverChannel);
    client = new SslPeer(clientName, clientSSLEngine, clientChannel);

    clientSSLEngine.beginHandshake();
    serverSSLEngine.beginHandshake();

    Runnable serverHandshakeRunnable = () -> {
      try {
        server.doHandshake();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    };

    Runnable clientHandshakeRunnable = () -> {
      try {
        client.doHandshake();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    };

    final CompletableFuture<Void> future = CompletableFuture.allOf(
        CompletableFuture.runAsync(serverHandshakeRunnable),
        CompletableFuture.runAsync(clientHandshakeRunnable));

    future.get();
  }
}
