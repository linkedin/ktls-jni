package com.linkedin.ktls;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class SslEngineGenerator {
  private static final String KEY_ALIAS = "main";
  private static final String CERT_ALIAS = "main";
  private static final char[] PASSWORD = "password".toCharArray();
  private static final int KEY_SIZE_BITS = 1024;

  public static Certificate selfSign(KeyPair keyPair, String subjectDN) throws Exception {
    Provider bcProvider = new BouncyCastleProvider();
    Security.addProvider(bcProvider);

    Instant now = Instant.now();

    X500Name dnName = new X500Name(subjectDN);
    // Using the current timestamp as the certificate serial number
    BigInteger certSerialNumber = new BigInteger(Long.toString(now.toEpochMilli()));

    String signatureAlgorithm = "SHA256WithRSA";

    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

    JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        dnName, certSerialNumber, Date.from(now), Date.from(now.plus(1, ChronoUnit.DAYS)), dnName, keyPair.getPublic());

    // Extensions --------------------------

    // Basic Constraints
    BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

    // Basic Constraints is usually marked as critical.
    certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);
    // -------------------------------------

    return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
  }

  private KeyPair createKeyPair() throws Exception {
    final KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
    rsaKeyPairGenerator.initialize(KEY_SIZE_BITS);

    return rsaKeyPairGenerator.generateKeyPair();
  }

  private void initializeStores() throws Exception {
    keyStore.load(null, null);
    trustStore.load(null, null);

    final Certificate certificate = selfSign(keyPair, String.format("cn=%s", getClass().getName()));
    keyStore.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), PASSWORD, new Certificate[]{certificate});
    trustStore.setCertificateEntry(CERT_ALIAS, certificate);
  }

  final String protocolToTest;
  final KeyPair keyPair;
  final KeyStore keyStore = KeyStore.getInstance("jks");
  final KeyStore trustStore = KeyStore.getInstance("jks");
  final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
  final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
  final SSLContext sslContext = SSLContext.getInstance("TLS", "SunJSSE");
  final SSLEngine serverSSLEngine;
  final SSLEngine clientSSLEngine;

  public SslEngineGenerator(String protocolToTest,
      String cipherSuiteToTest) throws Exception {
    this.protocolToTest = protocolToTest;
    keyPair = createKeyPair();
    initializeStores();

    keyManagerFactory.init(keyStore, PASSWORD);
    trustManagerFactory.init(trustStore);

    sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
    serverSSLEngine = sslContext.createSSLEngine();
    serverSSLEngine.setUseClientMode(false);
    serverSSLEngine.setNeedClientAuth(false);
    serverSSLEngine.setWantClientAuth(false);
    serverSSLEngine.setEnabledProtocols(new String[]{protocolToTest});
    serverSSLEngine.setEnabledCipherSuites(new String[]{cipherSuiteToTest});

    clientSSLEngine = sslContext.createSSLEngine("client", 80);
    serverSSLEngine.setEnabledProtocols(new String[]{protocolToTest});
    serverSSLEngine.setEnabledCipherSuites(new String[]{cipherSuiteToTest});
    clientSSLEngine.setUseClientMode(true);
  }

  public SSLEngine getServerSSLEngine() {
    return serverSSLEngine;
  }

  public SSLEngine getClientSSLEngine() {
    return clientSSLEngine;
  }
}
