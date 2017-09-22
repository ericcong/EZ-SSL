package io.cong.chen.ezssl;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public abstract class AbstractSSLBuilder <T extends AbstractSSLBuilder<T>>{
  private static String JKS = "JKS";
  private static String X509 = "SunX509";
  static String TLS = "TLS";

  KeyManager[] keyManagerList = null;
  TrustManager[] trustManagerList = null;

  private KeyStore getKeyStore(
      InputStream keyStoreInputStream,
      String keyStorePassword,
      String keyStoreAlgorithm)
      throws CertificateException, NoSuchAlgorithmException, IOException,
      KeyStoreException {
    char[] keyPairPasswordCharArray = keyStorePassword.toCharArray();
    KeyStore keyStore = KeyStore.getInstance(keyStoreAlgorithm);
    keyStore.load(keyStoreInputStream, keyPairPasswordCharArray);
    return keyStore;
  }

  public T setKeyStore(
      InputStream keyStoreInputStream,
      String keyStorePassword,
      String keyStoreAlgorithm,
      String keyPairAlgorithm)
      throws KeyStoreException, IOException, CertificateException,
      NoSuchAlgorithmException, UnrecoverableKeyException {

    KeyStore keyStore =
        getKeyStore(keyStoreInputStream, keyStorePassword, keyStoreAlgorithm);

    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(keyPairAlgorithm);
    keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());

    this.keyManagerList = keyManagerFactory.getKeyManagers();

    return (T) this;
  }

  public T setTrustedKeyStore(
      InputStream keyStoreInputStream,
      String keyStorePassword,
      String keyStoreAlgorithm,
      String keyPairAlgorithm)
      throws KeyStoreException, IOException, CertificateException,
      NoSuchAlgorithmException, UnrecoverableKeyException {

    KeyStore keyStore =
        getKeyStore(keyStoreInputStream, keyStorePassword, keyStoreAlgorithm);

    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(keyPairAlgorithm);
    trustManagerFactory.init(keyStore);

    this.trustManagerList = trustManagerFactory.getTrustManagers();

    return (T) this;
  }

  public T setJKS(
      InputStream jksInputStream, String jksPassword)
      throws UnrecoverableKeyException, CertificateException,
      NoSuchAlgorithmException, KeyStoreException, IOException {
    BufferedInputStream bufferedInputStream =
        new BufferedInputStream(jksInputStream);
    bufferedInputStream.mark(Integer.MAX_VALUE);
    this.setKeyStore(bufferedInputStream, jksPassword, JKS, X509);
    bufferedInputStream.reset();
    this.setTrustedKeyStore(bufferedInputStream, jksPassword, JKS, X509);
    bufferedInputStream.close();
    return (T) this;
  }

  public T setTrustedJKS(
      InputStream jksInputStream, String jksPassword)
      throws UnrecoverableKeyException, CertificateException,
      NoSuchAlgorithmException, KeyStoreException, IOException {
    return this.setTrustedKeyStore(jksInputStream, jksPassword, JKS, X509);
  }
}
