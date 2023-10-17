package io.phoenix_legacy.crypto;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public abstract class AbstractEncryption {

    protected static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    protected static final int AES_KEY_SIZE = 256;
    protected static final String SECRET_KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    protected static final int SECRET_KEY_DERIVATION_ITERATIONS = 1024;
    protected static final String RSA_ALGORITHM = "RSA/ECB/OAEPPadding";

    public  AsymmetricallyEncryptedData encryptLargeBytesAsymmetrically(byte[] bytesToEncrypt, byte[] publicKeyBytes) {
        PublicKey publicKey = decodePublicKey(publicKeyBytes);
        byte[] password = new byte[190];
        byte[] salt = new byte[190];
        Random random = getRandom();
        random.nextBytes(password);
        random.nextBytes(salt);

        Cipher cipher = getAsymmetricCipher(publicKey);
        byte[] encryptPassword = encryptAsymmetrically(cipher, password, "Failed to encrypt password");
        SecretKey secretKey = deriveSecretKey(password, salt);
        Cipher symmetricCipher = getSymmetricCipher(secretKey);
        EncryptionResult encryptionResult = encryptSymmetrically(symmetricCipher, bytesToEncrypt, "Failed to encrypt payload");
        return new AsymmetricallyEncryptedData(encryptionResult.cipherText, encryptPassword, salt, encryptionResult.iv);
    }

    public byte[] decryptLargeBytesAsymmetrically(String encryptionKeyAlias, AsymmetricallyEncryptedData data) {
        Cipher asymmetricCipher = getAsymmetricCipher(encryptionKeyAlias);
        byte[] decryptedPassword = decrypt(asymmetricCipher, data.encryptedPassword, "Failed to decrypt password");
        SecretKey secretKey = deriveSecretKey(decryptedPassword, data.salt);
        Cipher symmetricCipher = getSymmetricCipher(secretKey, data.iv);
        return decrypt(symmetricCipher, data.cipherText, "Failed to decrypt cipherText");
    }

    protected abstract Random getRandom();

    protected abstract Cipher getAsymmetricCipher(PublicKey publicKey);

    protected abstract Cipher getAsymmetricCipher(String alias);

    protected abstract Cipher getSymmetricCipher(SecretKey secretKey, byte[] iv);

    protected abstract Cipher getSymmetricCipher(SecretKey secretKey);

    protected static OAEPParameterSpec getOAEPParameterSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    }

    @Nullable
    protected abstract PrivateKey getPrivateKey(String alias);

    protected PublicKey decodePublicKey(byte[] publicKeyBytes) {
        try {
            String algorithm = SubjectPublicKeyInfo.getInstance(publicKeyBytes).getAlgorithm().getAlgorithm().getId();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decode public key", e);
        }
    }

    protected SecretKey deriveSecretKey(byte[] password, byte[] salt) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password, salt, SECRET_KEY_DERIVATION_ITERATIONS);
        CipherParameters cipherParameters = generator.generateDerivedParameters(AES_KEY_SIZE);
        return new BCPBEKey(SECRET_KEY_DERIVATION_ALGORITHM, cipherParameters);
    }

    protected byte[] decrypt(Cipher asymmetricCipher, byte[] payload, String errorMessage) {
        try {
            return asymmetricCipher.doFinal(payload);
        } catch (Exception e) {
            throw new RuntimeException(errorMessage, e);
        }
    }

    protected byte[] encryptAsymmetrically(Cipher cipher, byte[] cipherText, String errorMessage) {
        try {
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            throw new RuntimeException(errorMessage, e);
        }
    }

    protected EncryptionResult encryptSymmetrically(Cipher cipher, byte[] payload, String errorMessage) {
        try {
            byte[] cipherText = cipher.doFinal(payload);
            byte[] iv = cipher.getIV();
            return new EncryptionResult(cipherText,iv);
        } catch (Exception e) {
            throw new RuntimeException(errorMessage, e);
        }
    }

    public static class AsymmetricallyEncryptedData {
        private final byte[] cipherText;
        private final byte[] encryptedPassword;
        private final byte[] salt;
        private final byte[] iv;

        public AsymmetricallyEncryptedData(byte[] cipherText, byte[] encryptedPassword, byte[] salt, byte[] iv) {
            this.cipherText = cipherText;
            this.encryptedPassword = encryptedPassword;
            this.salt = salt;
            this.iv = iv;
        }

        public byte[] getCipherText() {
            return copyOf(cipherText);
        }

        public byte[] getEncryptedPassword() {
            return copyOf(encryptedPassword);
        }

        public byte[] getSalt() {
            return copyOf(salt);
        }

        public byte[] getIv() {
            return copyOf(iv);
        }

        private static byte[] copyOf(byte[] data) {
            return Arrays.copyOf(data, data.length);
        }
    }

    public static class EncryptionResult {
        private byte[] cipherText;
        private byte[] iv;

        public EncryptionResult(byte[] cipherText, byte[] iv) {
            this.cipherText = cipherText;
            this.iv = iv;
        }

        public byte[] getCipherText() {
            return copyOf(cipherText);
        }

        public byte[] getIv() {
            return copyOf(iv);
        }

        private static byte[] copyOf(byte[] data) {
            return Arrays.copyOf(data, data.length);
        }
    }
}
