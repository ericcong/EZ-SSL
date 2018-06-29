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
  public static String KEY_STORE_TYPE = "PKCS12";
  public static String KEY_PAIR_ALGORITHM = "SunX509";
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

  public T setTrustedKeyStore(KeyStore trustedKeyStore, String keyPairAlgorithm)
      throws NoSuchAlgorithmException,KeyStoreException {
    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(keyPairAlgorithm);
    trustManagerFactory.init(trustedKeyStore);
    this.trustManagerList = trustManagerFactory.getTrustManagers();
    return (T) this;
  }

  public T setTrustedKeyStore(KeyStore trustedKeyStore)
      throws NoSuchAlgorithmException,KeyStoreException {
    return setTrustedKeyStore(trustedKeyStore, KEY_PAIR_ALGORITHM);
  }

  public T setTrustedKeyStore(
      byte[] keyStoreByteArray,
      String keyStorePassword,
      String keyStoreType,
      String keyPairAlgorithm)
      throws KeyStoreException,
      IOException,
      CertificateException,
      NoSuchAlgorithmException {
    KeyStore keyStore =
        loadKeyStore(keyStoreByteArray, keyStorePassword, keyStoreType);
    return setTrustedKeyStore(keyStore, keyPairAlgorithm);
  }

  public T setTrustedKeyStore(byte[] keyStoreByteArray, String keyStorePassword)
      throws CertificateException,
      NoSuchAlgorithmException, KeyStoreException, IOException {
    return setTrustedKeyStore(
        keyStoreByteArray,
        keyStorePassword,
        KEY_STORE_TYPE,
        KEY_PAIR_ALGORITHM);
  }

  public T setKeyStore(
      KeyStore keyStore, String keyStorePassword, String keyPairAlgorithm)
      throws NoSuchAlgorithmException,
      UnrecoverableKeyException,
      KeyStoreException {
    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(keyPairAlgorithm);
    keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
    this.keyManagerList = keyManagerFactory.getKeyManagers();
    return (T) this;
  }

  public T setKeyStore(KeyStore keyStore, String keyStorePassword)
      throws UnrecoverableKeyException,
      NoSuchAlgorithmException,
      KeyStoreException {
    return setKeyStore(keyStore, keyStorePassword, KEY_PAIR_ALGORITHM);
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
    return setKeyStore(keyStore, keyStorePassword, keyPairAlgorithm);
  }

  public T setKeyStore(byte[] keyStoreByteArray, String keyStorePassword)
      throws UnrecoverableKeyException, CertificateException,
      NoSuchAlgorithmException, KeyStoreException, IOException {
    return setKeyStore(
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
}
