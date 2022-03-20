package com.reactnativedevicecrypto;

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
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;

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

  public DeviceCryptoModule(ReactApplicationContext reactContext) {
    super(reactContext);
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
      if (!Device.isCompatible(context, options)) {
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
      if (Helpers.doNonAuthenticatedCryptography(alias, Helpers.KeyType.SIGNING, context)) {
        String signatureOfTheText = Helpers.sign(plainText, signature);
        if (signatureOfTheText.isEmpty()) {
          throw new Exception("Couldn't sign the text");
        }
        promise.resolve(signatureOfTheText);
        return;
      }

      // Restricted key requires biometric authentication
      BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);
      Authenticator.authenticate(options, getCurrentActivity(), cryptoObject)
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
  public void encrypt(@NonNull String alias, String plainText, ReadableMap options, @NonNull final Promise promise) {
    try {
      ReactApplicationContext context = getReactApplicationContext();
      Cipher cipher = Helpers.initializeEncrypter(alias);

      // Key usage doesn't require biometric authentication (unrestricted)
      if (Helpers.doNonAuthenticatedCryptography(alias, Helpers.KeyType.SYMMETRIC_ENCRYPTION, context)) {
        Helpers.EncryptionResult result = Helpers.encrypt(plainText, cipher);
        promise.resolve(Helpers.toWritableMap(result));
        return;
      }

      // Restricted key requires biometric authentication
      BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
      Authenticator.authenticate(options, getCurrentActivity(), cryptoObject)
        .whenCompleteAsync((result, throwable) -> {
          if (null != throwable) {
            promise.reject(E_ERROR, Helpers.getError(throwable));
            return;
          }
          try {
              Helpers.EncryptionResult encryptionResult = Helpers.encrypt(plainText, Objects.requireNonNull(result.getCipher()));
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
  public void encryptBytesAsymmetrically(@NonNull String base64PublicKeyASN1, @NonNull String base64bytesToEncrypt, @NonNull final Promise promise) {
    try {
      PublicKey publicKey = Helpers.decodeBase64PublicKeyASN1(base64PublicKeyASN1);
      byte[] bytesToEncrypt = Base64.decode(base64bytesToEncrypt, Base64.NO_WRAP);
      Cipher cipher = Helpers.initializeAsymmetricEncrypter(publicKey);
      Helpers.EncryptionResult result = Helpers.encryptBytes(bytesToEncrypt, cipher);
      promise.resolve(Helpers.toWritableMap(result));
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void encryptLargeBytesAsymmetrically(@NonNull String base64PublicKeyASN1, @NonNull String base64bytesToEncrypt, @NonNull final Promise promise) {
      try {
          SecureRandom random = new SecureRandom();
          byte[] passwordBytes = new byte[190];
          byte[] saltBytes = new byte[190];
          random.nextBytes(passwordBytes);
          random.nextBytes(saltBytes);
          String password = Base64.encodeToString(passwordBytes, Base64.NO_WRAP);
          String salt = Base64.encodeToString(saltBytes, Base64.NO_WRAP);

          PublicKey publicKey = Helpers.decodeBase64PublicKeyASN1(base64PublicKeyASN1);
          Cipher cipher = Helpers.initializeAsymmetricEncrypter(publicKey);
          Helpers.EncryptionResult passwordEncryptionResult = Helpers.encryptBytes(passwordBytes, cipher);

          SecretKey secretKey = Helpers.deriveSecretKey(password, saltBytes);
          Cipher symmetricCipher = Helpers.initializeEncrypter(secretKey);
          byte[] bytesToEncrypt = Base64.decode(base64bytesToEncrypt, Base64.NO_WRAP);
          Helpers.EncryptionResult encryptionResult = Helpers.encryptBytes(bytesToEncrypt, symmetricCipher);

          WritableMap result = Arguments.createMap();

          result.putString("salt", salt);
          result.putString("password", Base64.encodeToString(passwordEncryptionResult.cipherText, Base64.NO_WRAP));
          Helpers.write(encryptionResult,result);

          promise.resolve(result);
      } catch (Exception e) {
          promise.reject(E_ERROR, Helpers.getError(e));
      }
  }

  @ReactMethod
  public void decrypt(@NonNull String alias, @NonNull String plainText, String ivDecoded, @NonNull ReadableMap options, @NonNull final Promise promise) {
    try {
      ReactApplicationContext context = getReactApplicationContext();
      Cipher cipher = Helpers.initializeDecrypter(alias, ivDecoded);

      // Key usage doesn't require biometric authentication (unrestricted)
      if (Helpers.doNonAuthenticatedCryptography(alias, Helpers.KeyType.SYMMETRIC_ENCRYPTION, context)) {
        promise.resolve(Helpers.decrypt(plainText, cipher));
        return;
      }

      // Restricted key requires biometric authentication
      BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
      Authenticator.authenticate(options, getCurrentActivity(), cryptoObject)
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

  @ReactMethod
  public void decryptLargeBytesAsymmetrically(@NonNull String alias, @NonNull String base64PasswordBytes, @NonNull String base64Salt, @NonNull String base64bytesToDecrypt, @NonNull String base64bytesIV, @NonNull ReadableMap options, @NonNull final Promise promise) {
    try {
      ReactApplicationContext context = getReactApplicationContext();
      Cipher asymmetricCipher = Helpers.initializeAsymmetricDecrypter(alias);

      CompletableFuture<String> future = new CompletableFuture<>();

      // Key usage doesn't require biometric authentication (unrestricted)
      if (Helpers.doNonAuthenticatedCryptography(alias, Helpers.KeyType.ASYMMETRIC_ENCRYPTION, context)) {
        future.complete(Helpers.decryptBytes(base64PasswordBytes, asymmetricCipher));
      } else {
        // Restricted key requires biometric authentication
        BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(asymmetricCipher);
        Authenticator.authenticate(options, getCurrentActivity(), cryptoObject)
                .whenCompleteAsync((result, throwable) -> {
                  if (null != throwable) {
                    future.completeExceptionally(throwable);
                    return;
                  }
                  try {
                    future.complete(Helpers.decryptBytes(base64PasswordBytes, Objects.requireNonNull(result.getCipher())));
                  } catch (Exception e) {
                    future.completeExceptionally(e);
                  }
                });
      }
      future.whenCompleteAsync((password, throwable) -> {
        if (null != throwable) {
          promise.reject(E_ERROR, Helpers.getError(throwable));
          return;
        }
        try {
          SecretKey secretKey = Helpers.deriveSecretKey(password, Base64.decode(base64Salt, Base64.NO_WRAP));
          Cipher cipher = Helpers.initializeDecrypter(secretKey, base64bytesIV);
          String decrypt = Helpers.decryptBytes(base64bytesToDecrypt, Objects.requireNonNull(cipher));
          promise.resolve(decrypt);
        } catch (Exception e) {
          promise.reject(E_ERROR, Helpers.getError(e));
        }
      });
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
      if (Helpers.doNonAuthenticatedCryptography(alias, Helpers.KeyType.ASYMMETRIC_ENCRYPTION, context)) {
        promise.resolve(Helpers.decryptBytes(cipherText, cipher));
        return;
      }

      // Restricted key requires biometric authentication
      BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
      Authenticator.authenticate(options, getCurrentActivity(), cryptoObject)
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
  public void getPublicKey(@NonNull String alias, @NonNull final Promise promise) {
    try {
      promise.resolve(Helpers.getPublicKeyPEMFormatted(alias));
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void getPublicKeyBytes(@NonNull String alias, @NonNull final Promise promise) {
    try {
      PublicKey publicKey = Helpers.getPublicKeyRef(alias);
      String encodedToString = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
      promise.resolve(encodedToString);
    } catch (Exception e) {
      promise.reject(E_ERROR, Helpers.getError(e));
    }
  }

  @ReactMethod
  public void isKeyExists(@NonNull String alias, @Helpers.KeyType.Types int keyType, @NonNull final Promise promise) {
    try {
      promise.resolve(Helpers.isKeyExists(alias, keyType));
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
      Authenticator.authenticate(options, getCurrentActivity())
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

}
