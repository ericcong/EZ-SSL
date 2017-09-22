package io.cong.chen.ezssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class SSLSocketBuilder extends AbstractSSLBuilder<SSLSocketBuilder> {
  public SSLSocket build(String hostname, int port, String sslProtocol)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    SSLContext sslContext = SSLContext.getInstance(sslProtocol);
    sslContext.init(this.keyManagerList, this.trustManagerList, null);

    SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

    SSLSocket sslSocket =
        (SSLSocket) sslSocketFactory.createSocket(hostname, port);
    sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

    return sslSocket;
  }

  public SSLSocket build(String hostname, int port)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    return this.build(hostname, port, TLS);
  }
}
