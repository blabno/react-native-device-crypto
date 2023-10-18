package io.phoenix_legacy.crypto;

import android.app.Activity;

import com.reactnativedevicecrypto.Authenticator;
import com.reactnativedevicecrypto.Helpers;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.biometric.BiometricPrompt;

public class AndroidEncryption extends AbstractEncryption {

    private final Activity activity;
    private final Map<String, Object> options;
    private final Random random;

    public AndroidEncryption(@NonNull Activity activity, @NonNull Map<String, Object> options, @NonNull Random random) {
        this.activity = activity;
        this.options = options;
        this.random = random;
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
            CompletableFuture<Cipher> future = new CompletableFuture<>();
            PrivateKey privateKey = getPrivateKey(alias);
            OAEPParameterSpec cipherAlgoParamSpec = getOAEPParameterSpec();
            Cipher asymmetricCipher = Cipher.getInstance(RSA_ALGORITHM);
            asymmetricCipher.init(Cipher.DECRYPT_MODE, privateKey, cipherAlgoParamSpec);
            if (Helpers.doNonAuthenticatedCryptography(alias, activity)) {
                future.complete(asymmetricCipher);
            } else {
                // Restricted key requires biometric authentication
                BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(asymmetricCipher);
                Authenticator.authenticate(options, activity, cryptoObject)
                        .whenCompleteAsync((result, throwable) -> {
                            if (null != throwable) {
                                future.completeExceptionally(throwable);
                                return;
                            }
                            future.complete(Objects.requireNonNull(result.getCipher()));
                        });
            }
            return future.join();
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to get cipher for algorithm: %s and alias: %s", AES_ALGORITHM, alias), e);
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

    @Override
    protected Cipher getSymmetricCipher(SecretKey secretKey, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to get cipher for algorithm: %s", AES_ALGORITHM), e);
        }
    }

    @Override
    protected Random getRandom() {
        return random;
    }

    @Nullable
    @Override
    protected PrivateKey getPrivateKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            return (PrivateKey) keyStore.getKey(alias, null);
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to get private key for alias: %s", alias));
        }
    }
}
