package com.reactnativedevicecrypto;


import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CryptoTests {

  private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  @BeforeClass
  public static void beforeClass() {
    if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
      Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
  }

  @Test
  public void symmetricEncryptionTest() throws Exception {
    KeyPair rsaKeyPair = generateRSAKeyPair();

    String password = randomString(190);
    String salt = randomString(190);

    String originalText = "Hello, World!";

    EncryptionResult encryptionResult = encrypt(originalText.getBytes(StandardCharsets.UTF_8), deriveSecretKey(password, fromBase64(salt)));

    System.out.println("Password: " + password);
    System.out.println("Salt: " + salt);
    System.out.println("EncryptionResult: " + encryptionResult);

    byte[] decryptedBytes = decrypt(fromBase64(toBase64(encryptionResult.cipherText)), deriveSecretKey(password, fromBase64(salt)), encryptionResult.initializationVector);

    System.out.println("decryptedBytes: " + Arrays.toString(decryptedBytes));
    System.out.println("decryptedBytes: " + toBase64(decryptedBytes));

    assertEquals(originalText, new String(decryptedBytes, StandardCharsets.UTF_8));

    String base64PublicKeyASN1 = toBase64(rsaKeyPair.getPublic().getEncoded());
    EncryptionResult encryptionResult2 = encryptBytesAsymmetrically(fromBase64(base64PublicKeyASN1), fromBase64(password));
    System.out.println("EncryptionResult2: " + encryptionResult2);
    byte[] bytesDecrypted = decryptBytesAsymmetrically(rsaKeyPair.getPrivate(), fromBase64(toBase64(encryptionResult2.cipherText)));
    System.out.println("bytesDecrypted asymmetrically: " + Arrays.toString(bytesDecrypted));
    assertArrayEquals(fromBase64(password), bytesDecrypted);
  }

  public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
    rsa.initialize(2048);
    return rsa.generateKeyPair();
  }

  public static String randomString(int length) {
    byte[] bytes = new byte[length];
    SECURE_RANDOM.nextBytes(bytes);
    return toBase64(bytes);
  }

  public static String toBase64(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  public static byte[] fromBase64(String text) {
    return Base64.getDecoder().decode(text);
  }

  public static SecretKey deriveSecretKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
    /* Derive the key, given password and salt. */
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
    SecretKey tmp = factory.generateSecret(spec);
    return new SecretKeySpec(tmp.getEncoded(), "AES");
  }

  public static byte[] decrypt(byte[] cipherText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    /* Decrypt the message, given derived key and initialization vector. */
    Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
    return cipher.doFinal(cipherText);
  }

  public static EncryptionResult encrypt(byte[] payload, SecretKey secret) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, secret);
    AlgorithmParameters params = cipher.getParameters();
    byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
    byte[] cipherText = cipher.doFinal(payload);
    return new EncryptionResult(cipherText, iv);
  }

  public EncryptionResult encryptBytesAsymmetrically(byte[] publicKeyBytes, byte[] bytesToEncrypt) throws Exception {
    String algorithm = SubjectPublicKeyInfo.getInstance(publicKeyBytes).getAlgorithm().getAlgorithm().getId();
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
    PublicKey publicKey = keyFactory.generatePublic(keySpec);
    Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    byte[] cipherText = cipher.doFinal(bytesToEncrypt);
    return new EncryptionResult(cipherText, null);
  }

  public byte[] decryptBytesAsymmetrically(PrivateKey privateKey, byte[] bytesToDecrypt) throws Exception {
    Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return cipher.doFinal(bytesToDecrypt);
  }

  public static class EncryptionResult {
    public byte[] initializationVector;
    public byte[] cipherText;

    public EncryptionResult(byte[] cipherText, byte[] initializationVector) {
      this.cipherText = cipherText;
      this.initializationVector = initializationVector;
    }

    @Override
    public String toString() {
      return "EncryptionResult{" +
        "initializationVector=" + Arrays.toString(initializationVector) +
        ", cipherText=" + Arrays.toString(cipherText) +
        '}';
    }
  }
}
