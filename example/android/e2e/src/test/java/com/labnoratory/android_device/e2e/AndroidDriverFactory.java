package com.labnoratory.android_device.e2e;

import io.appium.java_client.android.AndroidDriver;

public class AndroidDriverFactory {

    private static AndroidDriver instance;

    public static AndroidDriver getInstance() {
        if (null == instance) {
            throw new RuntimeException("AndroidDriver not provided");
        }
        return instance;
    }

    public static void setInstance(AndroidDriver instance) {
        AndroidDriverFactory.instance = instance;
    }
}
