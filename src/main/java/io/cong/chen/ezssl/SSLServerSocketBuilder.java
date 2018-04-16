package io.cong.chen.ezssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class SSLServerSocketBuilder extends
    AbstractSSLBuilder<SSLServerSocketBuilder> {
  public SSLServerSocket build(
      Integer port, Integer backlog, InetAddress ifAddress, String sslProtocol)
      throws NoSuchAlgorithmException,
      KeyManagementException,
      IOException,
      IllegalArgumentException {

    SSLContext sslContext = SSLContext.getInstance(sslProtocol);
    sslContext.init(this.keyManagerList, this.trustManagerList, null);

    SSLServerSocketFactory sslServerSocketFactory =
        sslContext.getServerSocketFactory();

    SSLServerSocket sslServerSocket = null;
    if (port == null && backlog == null && ifAddress == null) {
      sslServerSocket =
          (SSLServerSocket) sslServerSocketFactory.createServerSocket();
    } else if (port != null && backlog == null && ifAddress == null) {
      sslServerSocket =
          (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);
    } else if (port != null && backlog != null && ifAddress == null) {
      sslServerSocket = (SSLServerSocket) sslServerSocketFactory
          .createServerSocket(port, backlog);
    } else if (port != null && backlog != null) {
      sslServerSocket = (SSLServerSocket) sslServerSocketFactory
          .createServerSocket(port, backlog, ifAddress);
    } else {
      throw new IllegalArgumentException();
    }

    sslServerSocket.setEnabledCipherSuites(
        sslServerSocket.getSupportedCipherSuites());

    return sslServerSocket;
  }

  public SSLServerSocket build()
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(null, null, null, TLS);
  }

  public SSLServerSocket build(int port)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(port, null, null, TLS);
  }

  public SSLServerSocket build(int port, int backlog)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(port, backlog, null, TLS);
  }

  public SSLServerSocket build(int port, int backlog, InetAddress ifAddress)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(port, backlog, ifAddress, TLS);
  }
}