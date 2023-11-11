package com.reactnativedevicecrypto;

import android.app.Activity;
import android.content.Context;
import android.security.keystore.KeyInfo;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.module.annotations.ReactModule;
import com.labnoratory.android_crypto.AndroidAuthenticator;
import com.labnoratory.android_crypto.AndroidCrypto;
import com.labnoratory.android_crypto.EncryptionResult;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import androidx.annotation.NonNull;

import static com.reactnativedevicecrypto.Constants.BIOMETRY;
import static com.reactnativedevicecrypto.Constants.E_ERROR;
import static com.reactnativedevicecrypto.Constants.FACE;
import static com.reactnativedevicecrypto.Constants.IRIS;
import static com.reactnativedevicecrypto.Constants.NONE;
import static com.reactnativedevicecrypto.Constants.NOT_PROTECTED;
import static com.reactnativedevicecrypto.Constants.PIN_OR_PATTERN;
import static com.reactnativedevicecrypto.Constants.RN_MODULE;
import static com.reactnativedevicecrypto.Constants.TOUCH;

@SuppressWarnings({"unused", "SameParameterValue"})
@ReactModule(name = DeviceCryptoModule.NAME)
public class DeviceCryptoModule extends ReactContextBaseJavaModule {
  public static final String NAME = "DeviceCrypto";

  private final AndroidCrypto crypto;
  private final SecureRandom random;

  public DeviceCryptoModule(ReactApplicationContext reactContext) {
    super(reactContext);
    crypto = new AndroidCrypto();
    random = new SecureRandom();
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
    KeyType keyType = options.hasKey("keyType") ? KeyType.fromInt(options.getInt("keyType")) : KeyType.SIGNING;

    ReactApplicationContext context = getReactApplicationContext();

    try {
      boolean invalidateOnNewBiometry = options.hasKey("invalidateOnNewBiometry") && options.getBoolean("invalidateOnNewBiometry");
      AndroidCrypto.AccessLevel accessLevel = options.hasKey("accessLevel") ? AndroidCrypto.AccessLevel.fromInt(options.getInt("accessLevel")) : AndroidCrypto.AccessLevel.ALWAYS;
      if (!isCompatible(context, accessLevel)) {
        throw new Exception("The device cannot meet requirements. (Eg: not pin/pass protected or no biometry has been enrolled.");
      }

      if (KeyType.SIGNING.equals(keyType)) {
        PublicKey publicKey = crypto.createSigningKey(alias, accessLevel, invalidateOnNewBiometry);
        promise.resolve(getPublicKeyPEMFormatted(publicKey));
      } else if (KeyType.ASYMMETRIC_ENCRYPTION.equals(keyType)) {
        PublicKey publicKey = crypto.createAsymmetricEncryptionKey(alias, accessLevel, invalidateOnNewBiometry);
        promise.resolve(getPublicKeyPEMFormatted(publicKey));
      } else {
        SecretKey secretKey = crypto.createSymmetricEncryptionKey(alias, accessLevel, invalidateOnNewBiometry);
        promise.resolve(null);
      }
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, "Failed to create key"));
    }
  }

  @ReactMethod
  public void deleteKey(@NonNull String alias, @NonNull final Promise promise) {
    try {
      crypto.deleteKey(alias);
      promise.resolve(true);
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, "Failed to delete key"));
    }
  }

  @ReactMethod
  public void sign(@NonNull String alias, String payload, ReadableMap options, @NonNull final Promise promise) {
    String errorMessage = "Failed to sign";
    try {
      ReactApplicationContext context = getReactApplicationContext();
      byte[] payloadBytes = decodeBase64(payload);
      AndroidAuthenticator authenticator = new AndroidAuthenticator(requireCurrentActivity(), options.toHashMap());
      crypto.sign(alias, payloadBytes, authenticator)
              .whenCompleteAsync((result, throwable) -> {
                if (null != throwable) {
                  promise.reject(E_ERROR, getError(throwable, errorMessage));
                  return;
                }
                try {
                  promise.resolve(encodeBase64(result));
                } catch (Exception e) {
                  promise.reject(E_ERROR, getError(e, errorMessage));
                }
              });
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, errorMessage));
    }
  }

  @ReactMethod
  public void encryptSymmetrically(@NonNull String alias, String payload, ReadableMap options, @NonNull final Promise promise) {
    String errorMessage = "Failed to encrypt with symmetric key";
    try {
      ReactApplicationContext context = getReactApplicationContext();
      byte[] bytesToEncrypt = decodeBase64(payload);
      AndroidAuthenticator authenticator = new AndroidAuthenticator(requireCurrentActivity(), options.toHashMap());
      crypto.encryptSymmetrically(alias, bytesToEncrypt, authenticator)
              .whenCompleteAsync((encryptionResult, throwable) -> {
                if (null != throwable) {
                  promise.reject(E_ERROR, getError(throwable, errorMessage));
                  return;
                }
                try {
                  promise.resolve(toWritableMap(encryptionResult));
                } catch (Exception e) {
                  promise.reject(E_ERROR, getError(e, errorMessage));
                }
              });
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, errorMessage));
    }
  }

  @ReactMethod
  public void encryptSymmetricallyWithPassword(@NonNull String password, @NonNull String salt, int iterations, String payload, @NonNull final Promise promise) {
    String errorMessage = "Failed to encrypt with password";
    try {
      ReactApplicationContext context = getReactApplicationContext();
      byte[] bytesToEncrypt = decodeBase64(payload);
      EncryptionResult result = crypto.encryptSymmetricallyWithPassword(decodeBase64(password), decodeBase64(salt), iterations, bytesToEncrypt);
      promise.resolve(toWritableMap(result));
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, errorMessage));
    }
  }

  @ReactMethod
  public void encryptAsymmetrically(@NonNull String publicKeyDER, @NonNull String payload, @NonNull final Promise promise) {
    try {
      PublicKey publicKey = decodePublicKeyASN1(decodeBase64(publicKeyDER));
      byte[] bytesToEncrypt = decodeBase64(payload);
      byte[] result = crypto.encryptAsymmetrically(publicKey,bytesToEncrypt);
      promise.resolve(encodeBase64(result));
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, "Failed to encrypt with asymmetric key"));
    }
  }

  @ReactMethod
  public void decryptSymmetrically(@NonNull String alias, @NonNull String cipherText, String iv, @NonNull ReadableMap options, @NonNull final Promise promise) {
    String errorMessage = "Failed to decrypt with symmetric key";
    try {
      ReactApplicationContext context = getReactApplicationContext();
      byte[] cipherTextBytes = decodeBase64(cipherText);
      KeyInfo keyInfo = crypto.getKeyInfo(alias);
      checkKeyCompatibility(keyInfo, context);

      AndroidAuthenticator authenticator = new AndroidAuthenticator(requireCurrentActivity(), options.toHashMap());
      crypto.decryptSymmetrically(alias, cipherTextBytes, decodeBase64(iv), authenticator)
        .whenCompleteAsync((decryptedBytes, throwable) -> {
          if (null != throwable) {
            promise.reject(E_ERROR, getError(throwable, errorMessage));
            return;
          }
          try {
            promise.resolve(encodeBase64(decryptedBytes));
          } catch (Exception e) {
            promise.reject(E_ERROR, getError(e, errorMessage));
          }
        });
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, errorMessage));
    }
  }

  @ReactMethod
  public void decryptSymmetricallyWithPassword(@NonNull String password, @NonNull String salt, @NonNull String iv, int iterations, String cipherText, @NonNull final Promise promise) {
    String errorMessage = "Failed to decrypt with password";
    try {
      ReactApplicationContext context = getReactApplicationContext();
      byte[] cipherTextBytes = decodeBase64(cipherText);
      byte[] result = crypto.decryptSymmetricallyWithPassword(decodeBase64(password), decodeBase64(salt),iterations, cipherTextBytes, decodeBase64(iv));
      promise.resolve(encodeBase64(result));
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, errorMessage));
    }
  }

  @ReactMethod
  public void decryptAsymmetrically(@NonNull String alias, @NonNull String cipherText, @NonNull ReadableMap options, @NonNull final Promise promise) {
    String errorMessage = "Failed to decrypt with asymmetric key";
    try {
      byte[] cipherTextBytes = decodeBase64(cipherText);
      ReactApplicationContext context = getReactApplicationContext();

      KeyInfo keyInfo = crypto.getKeyInfo(alias);
      checkKeyCompatibility(keyInfo, context);

      AndroidAuthenticator authenticator = new AndroidAuthenticator(requireCurrentActivity(), options.toHashMap());
      crypto.decryptAsymmetrically(alias, cipherTextBytes, authenticator)
        .whenCompleteAsync((decryptedBytes, throwable) -> {
          if (null != throwable) {
            promise.reject(E_ERROR, getError(throwable, errorMessage));
            return;
          }
          try {
            promise.resolve(encodeBase64(decryptedBytes));
          } catch (Exception e) {
            promise.reject(E_ERROR, getError(e, errorMessage));
          }
        });
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, errorMessage));
    }
  }


  // HELPERS
  // ______________________________________________
  @ReactMethod
  public void getRandomBytes(int length, @NonNull final Promise promise) {
    try {
      byte[] bytes = new byte[length];
      random.nextBytes(bytes);
      promise.resolve(encodeBase64(bytes));
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, "Failed to get public key PEM"));
    }
  }

  @ReactMethod
  public void getPublicKeyPEM(@NonNull String alias, @NonNull final Promise promise) {
    try {
      promise.resolve(getPublicKeyPEMFormatted(Objects.requireNonNull(crypto.getPublicKey(alias), "Key not found")));
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, "Failed to get public key PEM"));
    }
  }

  @ReactMethod
  public void getPublicKeyDER(@NonNull String alias, @NonNull final Promise promise) {
    try {
      PublicKey publicKey = Objects.requireNonNull(crypto.getPublicKey(alias), "Key not found");
      String encodedToString = encodeBase64(publicKey.getEncoded());
      promise.resolve(encodedToString);
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, "Failed to get public key DER"));
    }
  }

  @ReactMethod
  public void isKeyExists(@NonNull String alias, @NonNull final Promise promise) {
    try {
      promise.resolve(crypto.containsKey(alias));
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, "Failed to check if key exists"));
    }
  }

  @ReactMethod
  public void isBiometryEnrolled(@NonNull final Promise promise) {
    try {
      promise.resolve(Device.hasEnrolledBiometry(getReactApplicationContext()));
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, "Failed to check if biometry is enrolled"));
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
      promise.reject(E_ERROR, getError(e, "Failed to determine device security level"));
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
      promise.reject(E_ERROR, getError(e, "Failed to determine biometry type"));
    }
  }

  @ReactMethod
  public void authenticateWithBiometry(ReadableMap options, final Promise promise) {
    String errorMessage = "Failed to authenticate with biometry";
    try {
      AndroidAuthenticator authenticator = new AndroidAuthenticator(requireCurrentActivity(), options.toHashMap());
      authenticator.authenticate(null)
        .whenCompleteAsync((cryptoObject, throwable) -> {
          if (null != throwable) {
            promise.reject(E_ERROR, getError(throwable, errorMessage));
          } else {
            promise.resolve(null);
          }
        });
    } catch (Exception e) {
      promise.reject(E_ERROR, getError(e, errorMessage));
    }
  }

  private static byte[] decodeBase64(String data) {
    return Base64.decode(data, Base64.NO_WRAP);
  }

  private static String encodeBase64(byte[] data) {
    return Base64.encodeToString(data, Base64.NO_WRAP);
  }

  private static PublicKey decodePublicKeyASN1(byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
    String algorithm = SubjectPublicKeyInfo.getInstance(publicKeyBytes).getAlgorithm().getAlgorithm().getId();
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
    return keyFactory.generatePublic(keySpec);
  }

  private static EncryptionResult encrypt(@NonNull byte[] bytesToEncrypt, @NonNull Cipher cipher) throws IllegalBlockSizeException, BadPaddingException {
    byte[] encryptedBytes = cipher.doFinal(bytesToEncrypt);
    byte[] iv = cipher.getIV();
    return new EncryptionResult(encryptedBytes, iv);
  }

  private static String getPublicKeyPEMFormatted(@NonNull PublicKey publicKey)  {
    String pubStr = Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT);
    return String.format("-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----", pubStr);
  }

  private void checkKeyCompatibility(KeyInfo keyInfo, Context context) {
    if (keyInfo.isUserAuthenticationRequired()) {
      if (!Device.hasEnrolledBiometry(context))
        throw new RuntimeException("Device cannot sign/encrypt. (No biometry enrolled)");
      if (!Device.isAppGrantedToUseBiometry(context))
        throw new RuntimeException("The app is not granted to use biometry.");
    }
  }

  @NonNull
  private Activity requireCurrentActivity() {
    return Objects.requireNonNull(getCurrentActivity(), "@ReactMethod should be called only in context of Activity");
  }

  private static boolean isCompatible(@NonNull final Context context, @NonNull AndroidCrypto.AccessLevel accessLevel) {
    switch (accessLevel) {
      case UNLOCKED_DEVICE:
        return Device.hasPinOrPassword(context);
      case AUTHENTICATION_REQUIRED:
        return Device.hasEnrolledBiometry(context);
      default:
        return true;
    }
  }

  private static Optional<Boolean> getBoolean(ReadableMap options, String key) {
    if(options.hasKey(key)) return Optional.of(options.getBoolean(key));
    return Optional.empty();
  }

  private static boolean isInputBase64(ReadableMap options) {
    return getBoolean(options,"inputIsBase64").orElse(false);
  }

  private static String getError(Throwable e, String message) {
    String errorMessage = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
    Log.e(RN_MODULE, message, e);
    return errorMessage == null ? message : errorMessage;
  }

  private static WritableMap toWritableMap(EncryptionResult encryptionResult) {
    WritableMap jsObject = Arguments.createMap();
    write(encryptionResult, jsObject);
    return jsObject;
  }

  private static void write(EncryptionResult encryptionResult, WritableMap map) {
    byte[] initializationVector = encryptionResult.getInitializationVector();
    if (null != initializationVector)
      map.putString("initializationVector", encodeBase64(initializationVector));
    map.putString("cipherText", encodeBase64(encryptionResult.getCipherText()));
  }

  enum KeyType {
    SIGNING,
    SYMMETRIC_ENCRYPTION,
    ASYMMETRIC_ENCRYPTION;

    public static KeyType fromInt(int accessLevel) {
      switch (accessLevel) {
        case 0:
          return SIGNING;
        case 1:
          return SYMMETRIC_ENCRYPTION;
        case 2:
          return ASYMMETRIC_ENCRYPTION;
      }
      throw new IllegalArgumentException("Invalid key type");
    }
  }

}
