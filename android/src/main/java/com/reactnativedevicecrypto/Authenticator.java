package com.reactnativedevicecrypto;

import android.app.Activity;
import android.util.Log;

import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import static com.reactnativedevicecrypto.Constants.BIOMETRY_DESCRIPTION;
import static com.reactnativedevicecrypto.Constants.BIOMETRY_SUBTITLE;
import static com.reactnativedevicecrypto.Constants.BIOMETRY_TITLE;
import static com.reactnativedevicecrypto.Constants.RN_MODULE;

public class Authenticator {
  private static BiometricPrompt biometricPrompt;

  public static CompletableFuture<BiometricPrompt.CryptoObject> authenticate(@NonNull ReadableMap options, @NonNull Activity activity) {
    return authenticate(options, activity, null);
  }

  public static CompletableFuture<BiometricPrompt.CryptoObject> authenticate(@NonNull ReadableMap options, @NonNull Activity activity, @Nullable BiometricPrompt.CryptoObject cryptoObject) {
    CompletableFuture<BiometricPrompt.CryptoObject> future = new CompletableFuture<>();
    UiThreadUtil.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        try {
          Executor executor = Executors.newSingleThreadExecutor();
          String title = getString(options, "biometryTitle", BIOMETRY_TITLE);
          String subTitle = getString(options, "biometrySubTitle", BIOMETRY_SUBTITLE);
          String description = getString(options, "biometryDescription", BIOMETRY_DESCRIPTION);

          BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subTitle)
            .setDescription(description)
            .setNegativeButtonText("Cancel")
            .build();

          BiometricPrompt.AuthenticationCallback authCallback = new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
              super.onAuthenticationError(errorCode, errString);
              biometricPrompt.cancelAuthentication();
              future.completeExceptionally(new AuthenticationErrorException(errorCode, errString));
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
              super.onAuthenticationSucceeded(result);
              future.complete(result.getCryptoObject());
            }

            @Override
            public void onAuthenticationFailed() {
              super.onAuthenticationFailed();
              future.completeExceptionally(new AuthenticationFailedException());
            }
          };

          biometricPrompt = new BiometricPrompt((FragmentActivity) activity, executor, authCallback);
          if (null == cryptoObject) {
            biometricPrompt.authenticate(promptInfo);
          } else {
            biometricPrompt.authenticate(promptInfo, cryptoObject);
          }
        } catch (Exception e) {
          Log.e(RN_MODULE, e.getMessage());
        }
      }
    });
    return future;
  }

  private static String getString(ReadableMap options, String key, String defaultValue) {
    String result = options.hasKey("biometryTitle") ? options.getString("biometryTitle") : BIOMETRY_TITLE;
    if (options.hasKey(key)) {
      result = options.getString(key);
    }
    return null == result ? defaultValue : result;
  }
}
