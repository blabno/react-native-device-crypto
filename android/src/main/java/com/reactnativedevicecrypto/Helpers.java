package com.reactnativedevicecrypto;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;

import java.lang.annotation.Retention;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import androidx.annotation.IntDef;
import androidx.annotation.NonNull;

import static com.reactnativedevicecrypto.Constants.RN_MODULE;
import static java.lang.annotation.RetentionPolicy.SOURCE;
import static java.nio.charset.StandardCharsets.UTF_8;


public class Helpers {
    private static final String KEY_STORE = "AndroidKeyStore";
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPPadding";
    private static final int AES_KEY_SIZE = 256;
    public static final String PEM_HEADER = "-----BEGIN PUBLIC KEY-----\n";
    public static final String PEM_FOOTER = "-----END PUBLIC KEY-----";

    public interface KeyType {
        @Retention(SOURCE)
        @IntDef({SIGNING, SYMMETRIC_ENCRYPTION, ASYMMETRIC_ENCRYPTION})
        @interface Types {}
        int SIGNING = 0;
        int SYMMETRIC_ENCRYPTION = 1;
        int ASYMMETRIC_ENCRYPTION = 2;
    }

    public interface AccessLevel {
        @Retention(SOURCE)
        @IntDef({ALWAYS, UNLOCKED_DEVICE, AUTHENTICATION_REQUIRED})
        @interface Types {}
        int ALWAYS = 0;
        int UNLOCKED_DEVICE = 1;
        int AUTHENTICATION_REQUIRED = 2;
    }

    public static String getString(Map<String, Object> options, String key, String defaultValue) {
        return Optional.ofNullable(options.get(key)).map(Object::toString).orElse(defaultValue);
    }

    public static int getInt(Map<String, Object> options, String key, int defaultValue) {
        return Optional.ofNullable(options.get(key)).map(v -> {
            if (v instanceof Integer) return (Integer) v;
            try {
                return Integer.parseInt(v.toString());
            } catch (NumberFormatException ignore) {
                return defaultValue;
            }
        }).orElse(defaultValue);
    }

    public static String getError(Throwable e) {
        String errorMessage = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
        Log.e(RN_MODULE, errorMessage);
        return errorMessage;
    }

    public static KeyStore getKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE);
        keyStore.load(null);
        return keyStore;
    }

    public static KeyInfo getKeyInfo(@NonNull String alias) throws Exception {
        Key key = getKeyStore().getKey(alias, null);
        if (key instanceof SecretKey) {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEY_STORE);
            return (KeyInfo) secretKeyFactory.getKeySpec((SecretKey) key, KeyInfo.class);
        } else {
            KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), KEY_STORE);
            return factory.getKeySpec(key, KeyInfo.class);
        }
    }

    public static boolean isKeyExists(@NonNull String alias) throws Exception {
        KeyStore keyStore = Helpers.getKeyStore();
        return keyStore.containsAlias(alias);
    }

    public static boolean doNonAuthenticatedCryptography(@NonNull String alias, Context context) throws Exception {
        if (!Helpers.isKeyExists(alias)) throw new Exception(alias.concat(" is not exists in KeyStore"));
        KeyInfo keyInfo = Helpers.getKeyInfo(alias);
        if (keyInfo.isUserAuthenticationRequired()) {
            if (!Device.hasEnrolledBiometry(context)) throw new Exception("Device cannot sign/encrypt. (No biometry enrolled)");
            if (!Device.isAppGrantedToUseBiometry(context)) throw new Exception("The app is not granted to use biometry.");
        }

        // We always inverted for better usage
        return !keyInfo.isUserAuthenticationRequired();
    }

    protected static KeyGenParameterSpec.Builder getBuilder(@NonNull String alias, @NonNull @KeyType.Types int keyType, @NonNull ReadableMap options) throws Exception {
        int accessLevel = options.hasKey("accessLevel") ? options.getInt("accessLevel") : Helpers.AccessLevel.ALWAYS;
        boolean invalidateOnNewBiometry = !options.hasKey("invalidateOnNewBiometry") || options.getBoolean("invalidateOnNewBiometry");
        int purposes = KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY | KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT;
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, purposes);

        if (keyType == KeyType.SIGNING) {
            builder.setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setRandomizedEncryptionRequired(true);
        } else  if (keyType == KeyType.ASYMMETRIC_ENCRYPTION) {
            builder
                    .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setRandomizedEncryptionRequired(true);
        } else {
            builder.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true);
        }

        // Initial level is AccessLevel.ALWAYS
        switch (accessLevel) {
          case AccessLevel.UNLOCKED_DEVICE:
            builder.setUserAuthenticationRequired(false);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
              builder.setUnlockedDeviceRequired(true);
            }
            break;
          case AccessLevel.AUTHENTICATION_REQUIRED:
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

    // ASYMMETRIC KEY METHODS
    public static PublicKey getOrCreateSigningKey(@NonNull String alias, @NonNull ReadableMap options) throws Exception {
        if (isKeyExists(alias)) {
            return getPublicKeyRef(alias);
        }

        KeyGenParameterSpec.Builder builder = getBuilder(alias, KeyType.SIGNING, options);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEY_STORE);
        keyPairGenerator.initialize(builder.build());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair.getPublic();
    }

    public static PublicKey getOrCreateAsymmetricEncryptionKey(@NonNull String alias, @NonNull ReadableMap options) throws Exception {
        if (isKeyExists(alias)) {
            return getPublicKeyRef(alias);
        }

        KeyGenParameterSpec.Builder builder = getBuilder(alias, KeyType.ASYMMETRIC_ENCRYPTION, options);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEY_STORE);
        keyPairGenerator.initialize(builder.build());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair.getPublic();
    }

    public static PublicKey getPublicKeyRef(@NonNull String alias) throws Exception {
        if (!isKeyExists(alias)) {
            throw new Exception(alias.concat(" not found in keystore"));
        }
        KeyStore keyStore = getKeyStore();
        Certificate certificate = keyStore.getCertificate(alias);
        return certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKeyRef(@NonNull String alias) throws Exception {
        KeyStore keyStore = getKeyStore();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        return privateKey;
    }

    public static String getPublicKeyPEMFormatted(@NonNull String alias) throws Exception {
        if (!isKeyExists(alias)) {
            return null;
        }
        PublicKey publicKey = getPublicKeyRef(alias);
        byte[] pubBytes = Base64.encode(publicKey.getEncoded(), Base64.DEFAULT);
        String pubStr = new String(pubBytes);
        return PEM_HEADER.concat(pubStr).concat(PEM_FOOTER);
    }

    public static Signature initializeSignature(@NonNull String alias) throws Exception {
        PrivateKey privateKey = Helpers.getPrivateKeyRef(alias);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        return signature;
    }

    public static String sign(@NonNull String textToBeSigned, @NonNull Signature signature) throws Exception {
        signature.update(textToBeSigned.getBytes(UTF_8));
        byte[] signatureBytes = signature.sign();
        byte[] signatureEncoded = Base64.encode(signatureBytes, Base64.NO_WRAP);
        return new String(signatureEncoded);
    }


    // SYMMETRIC KEY METHODS
    // ______________________________________________
    public static SecretKey getOrCreateSymmetricEncryptionKey(@NonNull String alias, @NonNull ReadableMap options) throws Exception {
        if (isKeyExists(alias)) {
            return getSymmetricKeyRef(alias);
        }

        KeyGenParameterSpec.Builder builder = getBuilder(alias, KeyType.SYMMETRIC_ENCRYPTION, options);
        KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEY_STORE);
        keyGen.init(builder.build());
        return keyGen.generateKey();
    }

    public static SecretKey getSymmetricKeyRef(@NonNull String alias) throws Exception {
        KeyStore keyStore = getKeyStore();
        return (SecretKey) keyStore.getKey(alias, null);
    }

    public static Cipher initializeDecrypter(@NonNull String alias, @NonNull String ivDecoded) throws Exception {
        SecretKey secretKey = getSymmetricKeyRef(alias);
        return initializeDecrypter(secretKey,ivDecoded);
    }

    public static Cipher initializeDecrypter(@NonNull SecretKey secretKey, @NonNull String ivDecoded) throws Exception {
        byte[] iv = Base64.decode(ivDecoded, Base64.NO_WRAP);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return cipher;
    }

    public static String decrypt(@NonNull String textTobeDecrypted, @NonNull Cipher cipher) throws Exception {
        byte[] encrypted = Base64.decode(textTobeDecrypted, Base64.NO_WRAP);
        byte[] decryptedBytes = cipher.doFinal(encrypted);
        return new String(decryptedBytes);
    }

    public static String decryptBytes(@NonNull String textTobeDecrypted, @NonNull Cipher cipher) throws Exception {
        byte[] encrypted = Base64.decode(textTobeDecrypted, Base64.NO_WRAP);
        byte[] decryptedBytes = cipher.doFinal(encrypted);
        return Base64.encodeToString(decryptedBytes, Base64.NO_WRAP);
    }

    public static Cipher initializeEncrypter(@NonNull String alias) throws Exception {
        SecretKey secretKey = getSymmetricKeyRef(alias);
        return initializeEncrypter(secretKey);
    }

    public static Cipher initializeEncrypter(@NonNull SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher;
    }

    public static Cipher initializeAsymmetricEncrypter(@NonNull PublicKey publicKey) throws Exception {
        OAEPParameterSpec sp = getOAEPParameterSpec();
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, sp);
        return cipher;
    }

    public static Cipher initializeAsymmetricDecrypter(@NonNull String alias) throws Exception {
        OAEPParameterSpec sp = getOAEPParameterSpec();
        PrivateKey privateKey = getPrivateKeyRef(alias);
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, sp);
        return cipher;
    }

    public static EncryptionResult encrypt(@NonNull byte[] bytesToEncrypt, @NonNull Cipher cipher) throws Exception {
        byte[] encryptedBytes = cipher.doFinal(bytesToEncrypt);
        byte[] iv = cipher.getIV();
        return new EncryptionResult(encryptedBytes, iv);
    }

    //    TODO deriveSecretKey should take algo name and iteration count as params
    public static SecretKey deriveSecretKey(String password, byte[] salt) {
        /* Derive the key, given password and salt. */
        byte[] passwordBytes = Base64.decode(password, Base64.NO_WRAP);
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(passwordBytes, salt, 1024);
        CipherParameters cipherParameters = generator.generateDerivedParameters(AES_KEY_SIZE);
        return new BCPBEKey("PBKDF2WithHmacSHA256", cipherParameters);
    }

    public static PublicKey decodeBase64PublicKeyASN1(String base64PublicKeyASN1) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.decode(base64PublicKeyASN1, Base64.NO_WRAP);
        String algorithm = SubjectPublicKeyInfo.getInstance(publicKeyBytes).getAlgorithm().getAlgorithm().getId();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }

    @NonNull
    private static OAEPParameterSpec getOAEPParameterSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    }

    public static WritableMap toWritableMap(EncryptionResult encryptionResult) {
        WritableMap jsObject = Arguments.createMap();
        write(encryptionResult, jsObject);
        return jsObject;
    }

    public static void write(EncryptionResult encryptionResult, WritableMap map) {
        if (null != encryptionResult.initializationVector)
            map.putString("initializationVector", Base64.encodeToString(encryptionResult.initializationVector, Base64.NO_WRAP));
        map.putString("cipherText", Base64.encodeToString(encryptionResult.cipherText, Base64.NO_WRAP));
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
