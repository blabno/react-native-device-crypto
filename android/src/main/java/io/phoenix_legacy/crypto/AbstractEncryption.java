package io.phoenix_legacy.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;

import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public abstract class AbstractEncryption {

    protected static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    protected static final int AES_KEY_SIZE = 256;
    protected static final String SECRET_KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    protected static final int SECRET_KEY_DERIVATION_ITERATIONS = 1024;
    protected static final String RSA_ALGORITHM = "RSA/ECB/OAEPPadding";

    public enum CipherMode {

        ENCRYPT(Cipher.ENCRYPT_MODE),
        DECRYPT(Cipher.DECRYPT_MODE);

        private final int opMode;

        CipherMode(int opMode) {
            this.opMode = opMode;
        }

        public int getOpMode() {
            return opMode;
        }
    }

    public byte[] decryptLargeBytesAsymmetrically(String encryptionKeyAlias, AsymmetricallyEncryptedData data) {
        Cipher asymmetricCipher = getAsymmetricCipher(encryptionKeyAlias, CipherMode.DECRYPT);
        byte[] decryptedPassword = decrypt(asymmetricCipher, data.encryptedPassword, "Failed to decrypt password");
        SecretKey secretKey = deriveSecretKey(decryptedPassword, data.salt);
        Cipher symmetricCipher = getSymmetricCipher(secretKey, data.iv, CipherMode.DECRYPT);
        return decrypt(symmetricCipher, data.cipherText, "Failed to decrypt cipherText");
    }

    protected abstract Cipher getSymmetricCipher(SecretKey secretKey, byte[] iv, CipherMode mode);

    protected abstract Cipher getAsymmetricCipher(String alias, CipherMode mode);

    protected static OAEPParameterSpec getOAEPParameterSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    }

    @Nullable
    protected abstract PrivateKey getPrivateKey(String alias);

    protected SecretKey deriveSecretKey(byte[] password, byte[] salt) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password, salt, SECRET_KEY_DERIVATION_ITERATIONS);
        CipherParameters cipherParameters = generator.generateDerivedParameters(AES_KEY_SIZE);
        return new BCPBEKey(SECRET_KEY_DERIVATION_ALGORITHM, cipherParameters);
    }


    protected byte[] decrypt(Cipher asymmetricCipher, byte[] encryptedPassword, String errorMessage) {
        try {
            return asymmetricCipher.doFinal(encryptedPassword);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
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
            return Arrays.copyOf(data,data.length);
        }
    }
}
