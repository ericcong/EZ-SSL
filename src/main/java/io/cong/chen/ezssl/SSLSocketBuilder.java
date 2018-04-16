package io.cong.chen.ezssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class SSLSocketBuilder extends AbstractSSLBuilder<SSLSocketBuilder> {
  public SSLSocket build(
      String hostname,
      InetAddress address,
      Integer port,
      InetAddress localAddress,
      Integer localPort, String sslProtocol)
      throws NoSuchAlgorithmException,
      KeyManagementException,
      IOException,
      IllegalArgumentException {
    SSLContext sslContext = SSLContext.getInstance(sslProtocol);
    sslContext.init(this.keyManagerList, this.trustManagerList, null);

    SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

    SSLSocket sslSocket = null;

    if (hostname == null
        && address == null
        && port == null
        && localAddress == null
        && localPort == null) {
      sslSocket = (SSLSocket) sslSocketFactory.createSocket();
    } else if (hostname == null
        && address != null
        && port != null
        && localAddress == null
        && localPort == null) {
      sslSocket = (SSLSocket) sslSocketFactory.createSocket(address, port);
    } else if (hostname == null
        && address != null
        && port != null
        && localAddress != null
        && localPort != null) {
      sslSocket = (SSLSocket) sslSocketFactory
          .createSocket(address, port, localAddress, localPort);
    } else if (hostname != null
        && address == null
        && port != null
        && localAddress == null
        && localPort == null) {
      sslSocket = (SSLSocket) sslSocketFactory.createSocket(hostname, port);
    } else if (hostname != null
        && address == null
        && port != null
        && localAddress != null
        && localPort != null) {
      sslSocket = (SSLSocket) sslSocketFactory
          .createSocket(hostname, port, localAddress, localPort);
    } else {
      throw new IllegalArgumentException();
    }

    sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

    return sslSocket;
  }

  public SSLSocket build()
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(null, null, null, null, null, TLS);
  }

  public SSLSocket build(InetAddress address, int port)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(null, address, port, null, null, TLS);
  }

  public SSLSocket build(
      InetAddress address, int port, InetAddress localAddress, int localPort)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(null, address, port, localAddress, localPort, TLS);
  }

  public SSLSocket build(String hostname, int port)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(hostname, null, port, null, null, TLS);
  }

  public SSLSocket build(
      String hostname, int port, InetAddress localAddress, int localPort)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(hostname, null, port, localAddress, localPort, TLS);
  }
}
