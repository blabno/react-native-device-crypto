package io.phoenix_legacy.crypto;

import com.reactnativedevicecrypto.CryptoTests;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class TestCrypto {

    public static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    public static final int AES_KEY_SIZE = 256;
    public static final String RSA_ALGORITHM = "RSA/ECB/OAEPPadding";
    public static final String SECRET_KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int SECRET_KEY_DERIVATION_ITERATIONS = 1024;

    public static SecretKey deriveSecretKey(byte[] password, byte[] salt) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password, salt, SECRET_KEY_DERIVATION_ITERATIONS);
        CipherParameters cipherParameters = generator.generateDerivedParameters(AES_KEY_SIZE);
        return new BCPBEKey(SECRET_KEY_DERIVATION_ALGORITHM, cipherParameters);
    }

    public static byte[] decrypt(byte[] cipherText, SecretKey secretKey, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return cipher.doFinal(cipherText);
    }

    public static byte[] decrypt(byte[] cipherText, byte[] password, byte[] salt, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey secretKey = deriveSecretKey(password, salt);
        return decrypt(cipherText, secretKey, iv);
    }

    public static byte[] decrypt(byte[] cipherText, KeyPair keyPair) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        OAEPParameterSpec parameterSpec = getOAEPParameterSpec();
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), parameterSpec);
        return cipher.doFinal(cipherText);
    }

    public static CryptoTests.EncryptionResult encryptSymmetrically(byte[] payload, SecretKey secret) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] cipherText = cipher.doFinal(payload);
        return new CryptoTests.EncryptionResult(cipherText, iv);
    }

    public static CryptoTests.EncryptionResult encryptSymmetrically(byte[] payload, byte[] password, byte[] salt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
        SecretKey secretKey = deriveSecretKey(password, salt);
        return encryptSymmetrically(payload, secretKey);
    }

    public static byte[] encryptBytesAsymmetrically(PublicKey publicKey, byte[] bytesToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        OAEPParameterSpec parameterSpec = getOAEPParameterSpec();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, parameterSpec);
        return cipher.doFinal(bytesToEncrypt);
    }

    public static byte[] encryptBytesAsymmetrically(byte[] publicKeyBytes, byte[] bytesToEncrypt) throws Exception {
        String algorithm = SubjectPublicKeyInfo.getInstance(publicKeyBytes).getAlgorithm().getAlgorithm().getId();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(bytesToEncrypt);
    }

    public static byte[] encryptBytesAsymmetrically(KeyPair keyPair, byte[] bytesToEncrypt) throws Exception {
        return encryptBytesAsymmetrically(keyPair.getPublic().getEncoded(), bytesToEncrypt);
    }


    public static OAEPParameterSpec getOAEPParameterSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    }
}
