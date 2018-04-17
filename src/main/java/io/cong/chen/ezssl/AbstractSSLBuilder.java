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
  private static String KEY_STORE_TYPE = "PKCS12";
  private static String KEY_PAIR_ALGORITHM = "SunX509";
  static String TLS = "TLS";

  KeyManager[] keyManagerList = null;
  TrustManager[] trustManagerList = null;

  private KeyStore loadKeyStore(
      byte[] keyStoreByteArray,
      String keyStorePassword,
      String keyStoreType)
      throws CertificateException, NoSuchAlgorithmException, IOException,
      KeyStoreException {
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);
    keyStore.load(
        new ByteArrayInputStream(keyStoreByteArray),
        keyStorePassword.toCharArray());
    return keyStore;
  }

  public T setKeyStore(
      byte[] keyStoreByteArray,
      String keyStorePassword,
      String keyStoreType,
      String keyPairAlgorithm)
      throws KeyStoreException, IOException, CertificateException,
      NoSuchAlgorithmException, UnrecoverableKeyException {

    KeyStore keyStore =
        loadKeyStore(keyStoreByteArray, keyStorePassword, keyStoreType);

    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(keyPairAlgorithm);
    keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());

    this.keyManagerList = keyManagerFactory.getKeyManagers();

    return (T) this;
  }

  public T setTrustedKeyStore(
      byte[] keyStoreByteArray,
      String keyStorePassword,
      String keyStoreType,
      String keyPairAlgorithm)
      throws KeyStoreException, IOException, CertificateException,
      NoSuchAlgorithmException, UnrecoverableKeyException {

    KeyStore keyStore =
        loadKeyStore(keyStoreByteArray, keyStorePassword, keyStoreType);

    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(keyPairAlgorithm);
    trustManagerFactory.init(keyStore);

    this.trustManagerList = trustManagerFactory.getTrustManagers();

    return (T) this;
  }

  public T setKeyStore(byte[] keyStoreByteArray, String keyStorePassword)
      throws UnrecoverableKeyException, CertificateException,
      NoSuchAlgorithmException, KeyStoreException, IOException {
    return this
        .setKeyStore(
            keyStoreByteArray,
            keyStorePassword,
            KEY_STORE_TYPE,
            KEY_PAIR_ALGORITHM)
        .setTrustedKeyStore(
            keyStoreByteArray,
            keyStorePassword,
            KEY_STORE_TYPE,
            KEY_PAIR_ALGORITHM);
  }

  public T setTrustedKeyStore(byte[] keyStoreByteArray, String keyStorePassword)
      throws UnrecoverableKeyException, CertificateException,
      NoSuchAlgorithmException, KeyStoreException, IOException {
    return this.setTrustedKeyStore(
        keyStoreByteArray,
        keyStorePassword,
        KEY_STORE_TYPE,
        KEY_PAIR_ALGORITHM);
  }
}
