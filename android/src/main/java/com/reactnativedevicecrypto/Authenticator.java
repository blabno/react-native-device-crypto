package com.reactnativedevicecrypto;

import android.app.Activity;
import android.util.Log;

import java.util.Map;
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
import static com.reactnativedevicecrypto.Helpers.getString;

public class Authenticator {
  private static BiometricPrompt biometricPrompt;

  public static CompletableFuture<BiometricPrompt.CryptoObject> authenticate(@NonNull Map<String, Object> options, @NonNull Activity activity) {
    return authenticate(options, activity, null);
  }

  public static CompletableFuture<BiometricPrompt.CryptoObject> authenticate(@NonNull Map<String, Object> options, @NonNull Activity activity, @Nullable BiometricPrompt.CryptoObject cryptoObject) {
    CompletableFuture<BiometricPrompt.CryptoObject> future = new CompletableFuture<>();
    activity.runOnUiThread(new Runnable() {
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
          Log.e(RN_MODULE, String.format("Failed to authenticate with biometry due to: %s", e.getMessage()));
        }
      }
    });
    return future;
  }
}
