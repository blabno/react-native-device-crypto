package com.labnoratory.android_device.e2e;

import java.io.IOException;

public class E2EHelper {

    public static final String PACKAGE_NAME = "com.devicecryptoexample";

    public static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public static void adb(String cmd) {
        try {
            Runtime.getRuntime().exec("adb " + cmd);
        } catch (IOException e) {
            throw new RuntimeException("Failed to emulate fingerprint scanning", e);
        }
    }

    public static void adbShell(String cmd) {
        adb("shell " + cmd);
    }

    public static void scanFinger(int fingerIndex) {
        adb("-e emu finger touch " + fingerIndex);
    }

    public static void scanEnrolledFinger() {
        scanFinger(1);
    }

    public static void scanUnknownFinger() {
        scanFinger(2);
    }

    public static void emulateBackButton() {
        adbShell("input keyevent 4");
    }
}
