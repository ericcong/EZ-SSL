package io.cong.chen.ezssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class SSLServerSocketBuilder extends
    AbstractSSLBuilder<SSLServerSocketBuilder> {
  public SSLServerSocket build(int port, String sslProtocol)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    SSLContext sslContext = SSLContext.getInstance(sslProtocol);
    sslContext.init(this.keyManagerList, this.trustManagerList, null);

    SSLServerSocketFactory sslServerSocketFactory =
        sslContext.getServerSocketFactory();

    SSLServerSocket sslServerSocket =
        (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);
    sslServerSocket.setEnabledCipherSuites(
        sslServerSocket.getSupportedCipherSuites());

    return sslServerSocket;
  }

  public SSLServerSocket build(int port)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(port, TLS);
  }
}