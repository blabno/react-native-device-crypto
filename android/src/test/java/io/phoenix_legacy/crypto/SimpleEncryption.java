package io.phoenix_legacy.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;

public class SimpleEncryption extends AbstractEncryption {

    private final Map<String, KeyPair> keyPairs = new HashMap<>();

    public KeyPair generateKeyPair(String alias) {
        KeyPair keyPair = generateRSAKeyPair();
        keyPairs.put(alias, keyPair);
        return keyPair;
    }

    @Override
    protected Cipher getSymmetricCipher(SecretKey secretKey, byte[] iv, CipherMode mode) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(mode.getOpMode(), secretKey, spec);
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to get symmetric cipher for algorithm: %s", AES_ALGORITHM), e);
        }
    }

    @Override
    protected Cipher getAsymmetricCipher(String alias, CipherMode mode) {
        try {
            PrivateKey privateKey = getPrivateKey(alias);
            OAEPParameterSpec cipherAlgoParamSpec = getOAEPParameterSpec();
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(mode.getOpMode(), privateKey, cipherAlgoParamSpec);
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to get asymmetric cipher for algorithm: %s and alias: %s", RSA_ALGORITHM, alias), e);
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
