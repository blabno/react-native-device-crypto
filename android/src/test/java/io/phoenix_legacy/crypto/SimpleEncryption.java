package io.phoenix_legacy.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;

public class SimpleEncryption extends AbstractEncryption {

    private final Map<String, KeyPair> keyPairs = new HashMap<>();

    private final Random random;

    public SimpleEncryption() {
        this(new Random());
    }

    public SimpleEncryption(Random random) {
        this.random = random;
    }

    public KeyPair generateKeyPair(String alias) {
        KeyPair keyPair = generateRSAKeyPair();
        keyPairs.put(alias, keyPair);
        return keyPair;
    }

    @Override
    protected Random getRandom() {
        return random;
    }

    @Override
    protected Cipher getAsymmetricCipher(PublicKey publicKey) {
        try {
            OAEPParameterSpec sp = getOAEPParameterSpec();
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, sp);
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to get asymmetric cipher for encryption: %s", RSA_ALGORITHM), e);
        }
    }

    @Override
    protected Cipher getAsymmetricCipher(String alias) {
        try {
            PrivateKey privateKey = getPrivateKey(alias);
            OAEPParameterSpec cipherAlgoParamSpec = getOAEPParameterSpec();
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, cipherAlgoParamSpec);
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to get asymmetric cipher for algorithm: %s and alias: %s", RSA_ALGORITHM, alias), e);
        }
    }

    @Override
    protected Cipher getSymmetricCipher(SecretKey secretKey, byte[] iv) {

        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to get symmetric cipher for algorithm: %s", AES_ALGORITHM), e);
        }
    }

    @Override
    protected Cipher getSymmetricCipher(SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to get cipher for algorithm: %s", AES_ALGORITHM), e);
        }
    }

    @Nullable
    @Override
    protected PrivateKey getPrivateKey(String alias) {
        return Optional.ofNullable(keyPairs.get(alias)).map(KeyPair::getPrivate).orElse(null);
    }

    public static KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }
}
