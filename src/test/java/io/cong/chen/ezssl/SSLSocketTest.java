package io.cong.chen.ezssl;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import java.io.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class SSLSocketTest {

  // Alpha.p12 includes Alpha's public/private key pair, it also trusts Boss's
  // public certificate.
  private static final String ALPHA_KEY_STORE_PATH = "/Alpha.p12";
  private static final String ALPHA_PASSWORD = "alphapass";
  private static final String ALPHA_PRINCIPAL_NAME = "CN=Alpha Department," +
      "OU=Alpha Department,O=chen.cong.io,L=Highland Park,ST=NJ,C=US";

  // Beta.p12 includes Beta's public/private key pair, it also trusts Boss's
  // public certificate.
  private static final String BETA_KEY_STORE_PATH = "/Beta.p12";
  private static final String BETA_PASSWORD = "betapass";
  private static final String BETA_PRINCIPAL_NAME = "CN=Beta Department," +
      "OU=Beta Department,O=chen.cong.io,L=Mountain View,ST=CA,C=US";

  // Trusted.p12 trusts Boss's public certificate.
  private static final String TRUSTED_KEY_STORE_PATH = "/Trusted.p12";
  private static final String TRUSTED_PASSWORD = "trustedpass";

  private static final String MESSAGE = "message";

  private static String mockMutation(String request) {
    return "Response for request: \"" + request + "\"";
  }

  private static byte[] alphaKeyStoreByteArray;
  private static byte[] betaKeyStoreByteArray;
  private static byte[] trustedKeyStoreByteArray;

  static {
    try {
      InputStream alphaKeyStoreInputStream =
          SSLSocketTest.class.getResourceAsStream(ALPHA_KEY_STORE_PATH);
      alphaKeyStoreByteArray =
          new byte[alphaKeyStoreInputStream.available()];
      alphaKeyStoreInputStream.read(alphaKeyStoreByteArray);

      InputStream betaKeyStoreInputStream =
          SSLSocketTest.class.getResourceAsStream(BETA_KEY_STORE_PATH);
      betaKeyStoreByteArray =
          new byte[betaKeyStoreInputStream.available()];
      betaKeyStoreInputStream.read(betaKeyStoreByteArray);

      InputStream trustedKeyStoreInputStream =
          SSLSocketTest.class.getResourceAsStream(TRUSTED_KEY_STORE_PATH);
      trustedKeyStoreByteArray =
          new byte[trustedKeyStoreInputStream.available()];
      trustedKeyStoreInputStream.read(trustedKeyStoreByteArray);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testSSLServerOnly() throws Exception {
    SSLServerSocket sslServerSocket = new SSLServerSocketBuilder()
        .setKeyStore(alphaKeyStoreByteArray, ALPHA_PASSWORD)
        .build(0);

    int port = sslServerSocket.getLocalPort();

    new Thread(() -> {
      try (SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept()) {
        BufferedReader in = new BufferedReader(
            new InputStreamReader(sslSocket.getInputStream()));
        BufferedWriter out = new BufferedWriter(
            new OutputStreamWriter(sslSocket.getOutputStream()));
        out.write(mockMutation(in.readLine()));
        out.newLine();
        out.flush();
      } catch (Exception e) {
        fail();
      }
    }).start();

    SSLSocket sslSocket = new SSLSocketBuilder()
        .setTrustedKeyStore(trustedKeyStoreByteArray, TRUSTED_PASSWORD)
        .build("localhost", port);

    BufferedWriter out = new BufferedWriter(
        new OutputStreamWriter(sslSocket.getOutputStream()));
    out.write(MESSAGE);
    out.newLine();
    out.flush();

    BufferedReader in = new BufferedReader(
        new InputStreamReader(sslSocket.getInputStream()));
    assertEquals(mockMutation(MESSAGE), in.readLine());

    assertEquals(ALPHA_PRINCIPAL_NAME,
        sslSocket.getSession().getPeerPrincipal().getName());

    sslSocket.close();
    sslServerSocket.close();
  }

  @Test
  public void testSSLOnBothSides() throws Exception {
    SSLServerSocket sslServerSocket = new SSLServerSocketBuilder()
        .setKeyStore(alphaKeyStoreByteArray, ALPHA_PASSWORD)
        .build(0);
    sslServerSocket.setNeedClientAuth(true);

    int port = sslServerSocket.getLocalPort();

    new Thread(() -> {
      try (SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept()) {
        BufferedReader in = new BufferedReader(
            new InputStreamReader(sslSocket.getInputStream()));
        BufferedWriter out = new BufferedWriter(
            new OutputStreamWriter(sslSocket.getOutputStream()));
        out.write(mockMutation(in.readLine()));
        out.newLine();
        out.write(sslSocket.getSession().getPeerPrincipal().getName());
        out.newLine();
        out.flush();
      } catch (Exception e) {
        fail();
      }
    }).start();

    SSLSocket sslSocket = new SSLSocketBuilder()
        .setKeyStore(betaKeyStoreByteArray, BETA_PASSWORD)
        .build("localhost", port);

    BufferedWriter out = new BufferedWriter(
        new OutputStreamWriter(sslSocket.getOutputStream()));
    out.write(MESSAGE);
    out.newLine();
    out.flush();

    BufferedReader in = new BufferedReader(
        new InputStreamReader(sslSocket.getInputStream()));
    assertEquals(mockMutation(MESSAGE), in.readLine());
    assertEquals(BETA_PRINCIPAL_NAME, in.readLine());

    assertEquals(ALPHA_PRINCIPAL_NAME,
        sslSocket.getSession().getPeerPrincipal().getName());

    sslSocket.close();
    sslServerSocket.close();
  }
}
