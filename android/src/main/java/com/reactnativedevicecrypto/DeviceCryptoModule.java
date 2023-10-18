package com.reactnativedevicecrypto;

import android.app.Activity;
import android.util.Base64;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.module.annotations.ReactModule;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Collections;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;
import io.phoenix_legacy.crypto.AbstractEncryption;
import io.phoenix_legacy.crypto.AndroidEncryption;

import static com.reactnativedevicecrypto.Constants.BIOMETRY;
import static com.reactnativedevicecrypto.Constants.E_ERROR;
import static com.reactnativedevicecrypto.Constants.FACE;
import static com.reactnativedevicecrypto.Constants.IRIS;
import static com.reactnativedevicecrypto.Constants.NONE;
import static com.reactnativedevicecrypto.Constants.NOT_PROTECTED;
import static com.reactnativedevicecrypto.Constants.PIN_OR_PATTERN;
import static com.reactnativedevicecrypto.Constants.TOUCH;

@SuppressWarnings({"unused", "SameParameterValue"})
@ReactModule(name = DeviceCryptoModule.NAME)
public class DeviceCryptoModule extends ReactContextBaseJavaModule {
  public static final String NAME = "DeviceCrypto";

  private final SecureRandom random;

  public DeviceCryptoModule(ReactApplicationContext reactContext) {
    super(reactContext);
    random = new SecureRandom();
    if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
      Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }


  // REACT METHODS
  // ______________________________________________
  @ReactMethod
  public void createKey(@NonNull String alias, @NonNull ReadableMap options, @NonNull final Promise promise) {
    int keyType = options.hasKey("keyType") ? options.getInt("keyType") : Helpers.KeyType.SIGNING;
    ReactApplicationContext context = getReactApplicationContext();

    try {
      if (!Device.isCompatible(context, options.toHashMap())) {
        throw new Exception("The device cannot meet requirements. (Eg: not pin/pass protected or no biometry has been enrolled.");
      }

      if (keyType == Helpers.KeyType.SIGNING) {
        PublicKey publicKey = Helpers.getOrCreateSigningKey(alias, options);
        if (publicKey == null) {
          throw new Exception("Public key is null.");
        }
        promise.resolve(Helpers.getPublicKeyPEMFormatted(alias));
      } else if (keyType == Helpers.KeyType.ASYMMETRIC_ENCRYPTION) {
        PublicKey publicKey = Helpers.getOrCreateAsymmetricEncryptionKey(alias, options);
        if (publicKey == null) {
          throw new Exception("Public key is null.");
        }
        promise.resolve(Helpers.getPublicKeyPEMFormatted(alias));
      } else {
        SecretKey secretKey = Helpers.getOrCreateSymmetricEncryptionKey(alias, options);
        if (secretKey == null) {
          throw new Exception("Secret key is null.");
        }
        promise.resolve(true);
      }
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void deleteKey(@NonNull String alias, @NonNull final Promise promise) {
    try {
      KeyStore keyStore = Helpers.getKeyStore();
      keyStore.deleteEntry(alias);
      promise.resolve(true);
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void sign(@NonNull String alias, String plainText, ReadableMap options, @NonNull final Promise promise) {
    try {
      ReactApplicationContext context = getReactApplicationContext();
      Signature signature = Helpers.initializeSignature(alias);

      // Key usage doesn't require biometric authentication (unrestricted)
      if (Helpers.doNonAuthenticatedCryptography(alias, context)) {
        String signatureOfTheText = Helpers.sign(plainText, signature);
        if (signatureOfTheText.isEmpty()) {
          throw new Exception("Couldn't sign the text");
        }
        promise.resolve(signatureOfTheText);
        return;
      }

      // Restricted key requires biometric authentication
      BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);
      Authenticator.authenticate(options.toHashMap(), requireCurrentActivity(), cryptoObject)
        .whenCompleteAsync((result, throwable) -> {
          if (null != throwable) {
            promise.reject(E_ERROR, Helpers.getError(throwable));
            return;
          }
          try {
            promise.resolve(Helpers.sign(plainText, Objects.requireNonNull(result.getSignature())));
          } catch (Exception e) {
            promise.reject(E_ERROR, Helpers.getError(e));
          }
        });
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void encryptSymmetrically(@NonNull String alias, String base64bytesToEncrypt, ReadableMap options, @NonNull final Promise promise) {
    try {
      ReactApplicationContext context = getReactApplicationContext();
      byte[] bytesToEncrypt = Base64.decode(base64bytesToEncrypt, Base64.NO_WRAP);
      Cipher cipher = Helpers.initializeEncrypter(alias);

      // Key usage doesn't require biometric authentication (unrestricted)
      if (Helpers.doNonAuthenticatedCryptography(alias, context)) {
        Helpers.EncryptionResult result = Helpers.encrypt(bytesToEncrypt, cipher);
        promise.resolve(Helpers.toWritableMap(result));
        return;
      }

      // Restricted key requires biometric authentication
      BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
      Authenticator.authenticate(options.toHashMap(), requireCurrentActivity(), cryptoObject)
        .whenCompleteAsync((result, throwable) -> {
          if (null != throwable) {
            promise.reject(E_ERROR, Helpers.getError(throwable));
            return;
          }
          try {
              Helpers.EncryptionResult encryptionResult = Helpers.encrypt(bytesToEncrypt, Objects.requireNonNull(result.getCipher()));
              promise.resolve(Helpers.toWritableMap(encryptionResult));
          } catch (Exception e) {
            promise.reject(E_ERROR, Helpers.getError(e));
          }
        });
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void encryptAsymmetrically(@NonNull String publicKeyDER, @NonNull String payload, @NonNull final Promise promise) {
    try {
      PublicKey publicKey = Helpers.decodeBase64PublicKeyASN1(publicKeyDER);
      byte[] bytesToEncrypt = Base64.decode(payload, Base64.NO_WRAP);
      Cipher cipher = Helpers.initializeAsymmetricEncrypter(publicKey);
      Helpers.EncryptionResult result = Helpers.encrypt(bytesToEncrypt, cipher);
      promise.resolve(encodeBase64(result.cipherText));
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }
    /**
     * Generates random password, salt and initialization vector. Password and salt are used
     * to derive symmetric secret key, which is used to encrypt payload.
     * <p>
     * The result is a map containing salt, password, iv and encryptedText.
     *
     * @param publicKeyDER base64 encoded DER representation of public key
     * @param payload base64 encoded bytes of payload to be encrypted
     * @param promise promise to return result through
     */
  @ReactMethod
  public void encryptLargeBytesAsymmetrically(@NonNull String publicKeyDER, @NonNull String payload, @NonNull final Promise promise) {
    try {
      ReactApplicationContext context = getReactApplicationContext();
      Activity currentActivity = requireCurrentActivity();
      byte[] publicKeyBytes = decodeBase64(publicKeyDER);
      byte[] bytesToEncrypt = decodeBase64(payload);
      AbstractEncryption.AsymmetricallyEncryptedData encryptedData = new AndroidEncryption(currentActivity, Collections.emptyMap(), random).encryptLargeBytesAsymmetrically(bytesToEncrypt, publicKeyBytes);
      WritableMap result = Arguments.createMap();

      result.putString("salt", encodeBase64(encryptedData.getSalt()));
      result.putString("encryptedPassword", encodeBase64(encryptedData.getEncryptedPassword()));
      result.putString("initializationVector", encodeBase64(encryptedData.getIv()));
      result.putString("cipherText", encodeBase64(encryptedData.getCipherText()));
      promise.resolve(result);
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void decryptSymmetrically(@NonNull String alias, @NonNull String plainText, String ivDecoded, @NonNull ReadableMap options, @NonNull final Promise promise) {
    try {
      ReactApplicationContext context = getReactApplicationContext();
      Cipher cipher = Helpers.initializeDecrypter(alias, ivDecoded);

      // Key usage doesn't require biometric authentication (unrestricted)
      if (Helpers.doNonAuthenticatedCryptography(alias, context)) {
        promise.resolve(Helpers.decrypt(plainText, cipher));
        return;
      }

      // Restricted key requires biometric authentication
      BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
      Authenticator.authenticate(options.toHashMap(), requireCurrentActivity(), cryptoObject)
        .whenCompleteAsync((result, throwable) -> {
          if (null != throwable) {
            promise.reject(E_ERROR, Helpers.getError(throwable));
            return;
          }
          try {
            promise.resolve(Helpers.decrypt(plainText, Objects.requireNonNull(result.getCipher())));
          } catch (Exception e) {
            promise.reject(E_ERROR, Helpers.getError(e));
          }
        });
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

    /**
     * Decrypts cipherText using initialization vector and symmetric key derived from salt, password.
     * Password comes from asymmetrically decrypting encryptedPassword using key designated by alias.
     *
     * @param alias alias of key to decrypt encryptedPassword
     * @param encryptedPassword base64 encoded bytes of encrypted encryptedPassword
     * @param salt base64 encoded salt
     * @param cipherText base64 encoded cipherText
     * @param iv base64 encoded initialization vector
     * @param options biometry options
     * @param promise promise to return result through
     */
  @ReactMethod
  public void decryptLargeBytesAsymmetrically(@NonNull String alias, @NonNull String cipherText, @NonNull String encryptedPassword, @NonNull String salt, @NonNull String iv, @NonNull ReadableMap options, @NonNull final Promise promise) {
    try {
      ReactApplicationContext context = getReactApplicationContext();
      AbstractEncryption.AsymmetricallyEncryptedData encryptedData = new AbstractEncryption.AsymmetricallyEncryptedData(decodeBase64(cipherText), decodeBase64(encryptedPassword), decodeBase64(salt), decodeBase64(iv));
      Activity currentActivity = requireCurrentActivity();
      byte[] decryptedBytes = new AndroidEncryption(currentActivity, options.toHashMap(), random).decryptLargeBytesAsymmetrically(alias, encryptedData);
      promise.resolve(encodeBase64(decryptedBytes));
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void decryptAsymmetrically(@NonNull String alias, @NonNull String cipherText, @NonNull ReadableMap options, @NonNull final Promise promise) {
    try {
      ReactApplicationContext context = getReactApplicationContext();
      Cipher cipher = Helpers.initializeAsymmetricDecrypter(alias);

      // Key usage doesn't require biometric authentication (unrestricted)
      if (Helpers.doNonAuthenticatedCryptography(alias, context)) {
        promise.resolve(Helpers.decryptBytes(cipherText, cipher));
        return;
      }

      // Restricted key requires biometric authentication
      BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
      Authenticator.authenticate(options.toHashMap(), requireCurrentActivity(), cryptoObject)
        .whenCompleteAsync((result, throwable) -> {
          if (null != throwable) {
            promise.reject(E_ERROR, Helpers.getError(throwable));
            return;
          }
          try {
            promise.resolve(Helpers.decryptBytes(cipherText, Objects.requireNonNull(result.getCipher())));
          } catch (Exception e) {
            promise.reject(E_ERROR, Helpers.getError(e));
          }
        });
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }


  // HELPERS
  // ______________________________________________
  @ReactMethod
  public void getPublicKeyPEM(@NonNull String alias, @NonNull final Promise promise) {
    try {
      promise.resolve(Helpers.getPublicKeyPEMFormatted(alias));
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void getPublicKeyDER(@NonNull String alias, @NonNull final Promise promise) {
    try {
      PublicKey publicKey = Helpers.getPublicKeyRef(alias);
      String encodedToString = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
      promise.resolve(encodedToString);
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void isKeyExists(@NonNull String alias, @NonNull final Promise promise) {
    try {
      promise.resolve(Helpers.isKeyExists(alias));
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void isBiometryEnrolled(@NonNull final Promise promise) {
    try {
      promise.resolve(Device.hasEnrolledBiometry(getReactApplicationContext()));
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void deviceSecurityLevel(@NonNull final Promise promise) {
    try {
      // Class 2 or Class 3 biometry
      if (Device.hasEnrolledBiometry(getReactApplicationContext())) {
        promise.resolve(BIOMETRY);
        return;
      }

      // Pin, password or pattern protected
      if (Device.hasPinOrPassword(getReactApplicationContext())) {
        promise.resolve(PIN_OR_PATTERN);
        return;
      }
      promise.resolve(NOT_PROTECTED);
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void getBiometryType(@NonNull final Promise promise) {
    try {
      if (Device.hasIrisAuth(getReactApplicationContext())) {
        promise.resolve(IRIS);
        return;
      }

      if (Device.hasFaceAuth(getReactApplicationContext())) {
        promise.resolve(FACE);
        return;
      }

      if (Device.hasFingerprint(getReactApplicationContext())) {
        promise.resolve(TOUCH);
        return;
      }

      promise.resolve(NONE);
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void authenticateWithBiometry(ReadableMap options, final Promise promise) {
    try {
      Authenticator.authenticate(options.toHashMap(), requireCurrentActivity())
        .whenCompleteAsync((cryptoObject, throwable) -> {
          if (null != throwable) {
            promise.reject(E_ERROR, Helpers.getError(throwable));
          } else {
            promise.resolve(true);
          }
        });
    } catch (Exception e) {
      Helpers.getError(e);
    }
  }

  private static byte[] decodeBase64(String data) {
    return Base64.decode(data, Base64.NO_WRAP);
  }

  private static String encodeBase64(byte[] data) {
    return Base64.encodeToString(data, Base64.NO_WRAP);
  }

  @NonNull
  private Activity requireCurrentActivity() {
    return Objects.requireNonNull(getCurrentActivity(), "@ReactMethod should be called only in context of Activity");
  }

}
