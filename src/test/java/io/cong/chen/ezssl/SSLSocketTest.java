package io.cong.chen.ezssl;

import org.junit.Test;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import java.io.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class SSLSocketTest {

  // Alpha.jks includes Alpha's public/private key pair, it also trusts Boss's
  // public certificate.
  private static String ALPHA_JKS_PATH = "/Alpha.jks";
  private static String ALPHA_PASSWORD = "alphapass";
  private static String ALPHA_PRINCIPAL_NAME = "CN=Alpha Department," +
      "OU=Alpha Department,O=chen.cong.io,L=Highland Park,ST=NJ,C=US";

  // Beta.jks includes Beta's public/private key pair, it also trusts Boss's
  // public certificate.
  private static String BETA_JKS_PATH = "/Beta.jks";
  private static String BETA_PASSWORD = "betapass";
  private static String BETA_PRINCIPAL_NAME = "CN=Beta Department," +
      "OU=Beta Department,O=chen.cong.io,L=Mountain View,ST=CA,C=US";

  // Trusted.jks trusts Boss's public certificate.
  private static String TRUSTED_JKS_PATH = "/Trusted.jks";
  private static String TRUSTED_PASSWORD = "trustedpass";

  private static String MESSAGE = "message";

  private String mockMutation(String request) {
    return "Response for request: \"" + request + "\"";
  }

  @Test
  public void testSSLServerOnly() throws Exception {
    SSLServerSocket sslServerSocket = new SSLServerSocketBuilder()
        .setJKS(this.getClass().getResourceAsStream(ALPHA_JKS_PATH),
            ALPHA_PASSWORD)
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
        .setTrustedJKS(this.getClass().getResourceAsStream(TRUSTED_JKS_PATH),
            TRUSTED_PASSWORD)
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
        .setJKS(this.getClass().getResourceAsStream(ALPHA_JKS_PATH),
            ALPHA_PASSWORD)
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
        .setJKS(this.getClass().getResourceAsStream(BETA_JKS_PATH),
            BETA_PASSWORD)
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
