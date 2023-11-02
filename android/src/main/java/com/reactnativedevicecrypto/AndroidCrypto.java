package com.reactnativedevicecrypto;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import androidx.annotation.NonNull;

public class AndroidCrypto {


    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPPadding";
    private static final String KEY_STORE = "AndroidKeyStore";
    private static final String SECRET_KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    public AndroidCrypto() {
        if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    public boolean containsKey(@NonNull String alias) throws KeyStoreException {
        return getKeyStore().containsAlias(alias);
    }

    public PublicKey createAsymmetricEncryptionKey(String alias, AccessLevel accessLevel, boolean invalidateOnNewBiometry) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenParameterSpec keyGenParameterSpec = getAsymmetricEncryptionKeyBuilder(alias, accessLevel,invalidateOnNewBiometry).build();
        String algorithm = KeyProperties.KEY_ALGORITHM_RSA;
        return generateKeyPair(keyGenParameterSpec, algorithm).getPublic();
    }

    public PublicKey createSigningKey(@NonNull String alias, @NonNull AccessLevel accessLevel, boolean invalidateOnNewBiometry) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenParameterSpec keyGenParameterSpec= getSigningKeyBuilder(alias, accessLevel, invalidateOnNewBiometry).build();
        String algorithm = KeyProperties.KEY_ALGORITHM_EC;
        return generateKeyPair(keyGenParameterSpec, algorithm).getPublic();
    }

    public SecretKey createSymmetricEncryptionKey(String alias, AccessLevel accessLevel, boolean invalidateOnNewBiometry) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenParameterSpec keyGenParameterSpec = getSymmetricEncryptionKeyBuilder(alias, accessLevel, invalidateOnNewBiometry).build();
        String algorithm = KeyProperties.KEY_ALGORITHM_AES;
        KeyGenerator generator = KeyGenerator.getInstance(algorithm, KEY_STORE);
        generator.init(keyGenParameterSpec);
        return generator.generateKey();
    }

    public void deleteKey(String alias) throws KeyStoreException {
        KeyStore keyStore = getKeyStore();
        keyStore.deleteEntry(alias);
    }

    public SecretKey deriveSecretKey(byte[] password, byte[] salt, int iterations) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password, salt, iterations);
        int AES_KEY_SIZE = 256;
        CipherParameters cipherParameters = generator.generateDerivedParameters(AES_KEY_SIZE);
        return new BCPBEKey(SECRET_KEY_DERIVATION_ALGORITHM, cipherParameters);
    }

    public KeyInfo getKeyInfo(@NonNull String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        Key key = getKeyStore().getKey(alias, null);
        if (null == key) {
            throw new RuntimeException(String.format("Key '%s' does not exist in key store", alias));
        }
        if (key instanceof SecretKey) {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEY_STORE);
            return (KeyInfo) factory.getKeySpec((SecretKey) key, KeyInfo.class);
        } else {
            KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), KEY_STORE);
            return factory.getKeySpec(key, KeyInfo.class);
        }
    }

    public Signature initializeSignature(@NonNull String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException {
        PrivateKey privateKey = (PrivateKey) getKeyStore().getKey(alias, null);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        return signature;
    }

    public Cipher initializeSymmetricCipherForEncryption(SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher;
    }

    public Cipher initializeSymmetricCipherForEncryption(@NonNull String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        SecretKey secretKey = (SecretKey) getKeyStore().getKey(alias, null);
        return initializeSymmetricCipherForEncryption(secretKey);
    }

    public  Cipher initializeSymmetricCipherForDecryption(@NonNull String alias, @NonNull byte[] iv) throws Exception {
        SecretKey secretKey = (SecretKey) getKeyStore().getKey(alias, null);
        return initializeSymmetricCipherForDecryption(secretKey, iv);
    }

    public  Cipher initializeSymmetricCipherForDecryption(@NonNull SecretKey secretKey, @NonNull byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return cipher;
    }

    public  Cipher initializeAsymmetricCipherForEncryption(@NonNull PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        OAEPParameterSpec sp = getOAEPParameterSpec();
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, sp);
        return cipher;
    }

    public  Cipher initializeAsymmetricCipherForDecryption(@NonNull String alias) throws Exception {
        OAEPParameterSpec sp = getOAEPParameterSpec();
        PrivateKey privateKey = (PrivateKey) getKeyStore().getKey(alias, null);
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, sp);
        return cipher;
    }

    public byte[] sign(@NonNull byte[] payload, @NonNull Signature signature) throws SignatureException {
        signature.update(payload);
        return signature.sign();
    }

    protected static KeyPair generateKeyPair(KeyGenParameterSpec keyGenParameterSpec, String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, KEY_STORE);
        generator.initialize(keyGenParameterSpec);
        return generator.generateKeyPair();
    }

    protected static KeyGenParameterSpec.Builder getAsymmetricEncryptionKeyBuilder(@NonNull String alias, @NonNull AccessLevel accessLevel, boolean invalidateOnNewBiometry) {
        KeyGenParameterSpec.Builder builder =   new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        builder
                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setRandomizedEncryptionRequired(true);
        return applyOptions(builder, accessLevel, invalidateOnNewBiometry);
    }

    protected static KeyGenParameterSpec.Builder getSigningKeyBuilder(@NonNull String alias, @NonNull AccessLevel accessLevel, boolean invalidateOnNewBiometry) {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setRandomizedEncryptionRequired(true);
        return applyOptions(builder, accessLevel, invalidateOnNewBiometry);
    }

    protected static KeyGenParameterSpec.Builder getSymmetricEncryptionKeyBuilder(@NonNull String alias, @NonNull AccessLevel accessLevel, boolean invalidateOnNewBiometry) {
        KeyGenParameterSpec.Builder builder =   new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        builder.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true);
        return applyOptions(builder, accessLevel, invalidateOnNewBiometry);
    }

    protected static KeyGenParameterSpec.Builder applyOptions(@NonNull KeyGenParameterSpec.Builder builder, @NonNull AccessLevel accessLevel, boolean invalidateOnNewBiometry) {
        switch (accessLevel) {
            case UNLOCKED_DEVICE:
                builder.setUserAuthenticationRequired(false);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    builder.setUnlockedDeviceRequired(true);
                }
                break;
            case AUTHENTICATION_REQUIRED:
                // Sets whether this key is authorized to be used only if the user has been authenticated.
                builder.setUserAuthenticationRequired(true);
                // Allow pin/pass as a fallback on API 30+
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_DEVICE_CREDENTIAL | KeyProperties.AUTH_BIOMETRIC_STRONG);
                }
                // Invalidate the keys if the user has registered a new biometric
                // credential. The variable "invalidatedByBiometricEnrollment" is true by default.
                builder.setInvalidatedByBiometricEnrollment(invalidateOnNewBiometry);
                if (Build.VERSION.SDK_INT > Build.VERSION_CODES.R) {
                    builder.setIsStrongBoxBacked(true);
                }
                break;
        }
        return builder;
    }

    protected static KeyStore getKeyStore()  {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE);
            keyStore.load(null);
            return keyStore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get key store", e);
        }
    }

    @NonNull
    protected static OAEPParameterSpec getOAEPParameterSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    }

    public PublicKey getPublicKey(String alias) throws KeyStoreException {
        return Optional.ofNullable(getKeyStore().getCertificate(alias)).map(Certificate::getPublicKey).orElse(null);
    }

    enum AccessLevel {
        ALWAYS,
        UNLOCKED_DEVICE,
        AUTHENTICATION_REQUIRED;

        public static AccessLevel fromInt(int accessLevel) {
            switch (accessLevel) {
                case 0:
                    return ALWAYS;
                case 1:
                    return UNLOCKED_DEVICE;
                case 2:
                    return AUTHENTICATION_REQUIRED;
            }
            throw new IllegalArgumentException("Invalid access level");
        }
    }
}
