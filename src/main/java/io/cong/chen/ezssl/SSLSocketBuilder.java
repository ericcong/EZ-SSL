package io.cong.chen.ezssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class SSLSocketBuilder extends AbstractSSLBuilder<SSLSocketBuilder> {

  private int connectTimeout = 0;

  public SSLSocketBuilder setConnectTimeout(int connectTimeout) {
    this.connectTimeout = connectTimeout;
    return this;
  }

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

    SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket();

    if (hostname == null
        && address != null
        && port != null
        && localAddress == null
        && localPort == null) {
      sslSocket.connect(new InetSocketAddress(address, port), connectTimeout);
    } else if (hostname == null
        && address != null
        && port != null
        && localAddress != null
        && localPort != null) {
      sslSocket.bind(new InetSocketAddress(localAddress, localPort));
      sslSocket.connect(new InetSocketAddress(address, port), connectTimeout);
    } else if (hostname != null
        && address == null
        && port != null
        && localAddress == null
        && localPort == null) {
      sslSocket.connect(new InetSocketAddress(hostname, port), connectTimeout);
    } else if (hostname != null
        && address == null
        && port != null
        && localAddress != null
        && localPort != null) {
      sslSocket.bind(new InetSocketAddress(localAddress, localPort));
      sslSocket.connect(new InetSocketAddress(hostname, port), connectTimeout);
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
