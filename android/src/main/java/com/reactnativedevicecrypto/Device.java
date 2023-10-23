package com.reactnativedevicecrypto;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import java.util.Map;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;

import static android.content.pm.PackageManager.PERMISSION_GRANTED;
import static androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG;
import static androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK;
import static androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL;
import static androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS;
import static com.reactnativedevicecrypto.Helpers.getInt;

public class Device {
    public static boolean hasEnrolledBiometry(@NonNull final Context context) {
        return BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG | BIOMETRIC_WEAK) == BIOMETRIC_SUCCESS;
    }

    public static boolean hasPinOrPassword(@NonNull final Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return BiometricManager.from(context).canAuthenticate(DEVICE_CREDENTIAL) == BIOMETRIC_SUCCESS;
        }

        KeyguardManager kg = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        return kg != null && kg.isDeviceSecure();
    }

    public static boolean hasFingerprint(@NonNull final Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_FINGERPRINT);
    }

    public static boolean hasFaceAuth(@NonNull final Context context) {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_FACE);
    }

    public static boolean hasIrisAuth(@NonNull final Context context) {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_IRIS);
    }

    public static boolean isAppGrantedToUseBiometry(@NonNull final Context context) {
        // It was USE_FINGERPRINT before Api28
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PERMISSION_GRANTED;
        }

        return context.checkSelfPermission(Manifest.permission.USE_BIOMETRIC) == PERMISSION_GRANTED;
    }

    public static boolean isCompatible(@NonNull final Context context, @NonNull Map<String, Object> options) {
      int accessLevel = getInt(options, "accessLevel", Helpers.AccessLevel.ALWAYS);
      switch (accessLevel) {
        case Helpers.AccessLevel.UNLOCKED_DEVICE:
          return hasPinOrPassword(context);
        case Helpers.AccessLevel.AUTHENTICATION_REQUIRED:
          return hasEnrolledBiometry(context);
        default:
          return true;
      }
    }
}
