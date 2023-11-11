package com.labnoratory.android_device.e2e;

import io.appium.java_client.AppiumBy;
import io.appium.java_client.android.AndroidDriver;

public class MainTabsFragment {

    private final AndroidDriver driver;

    public MainTabsFragment(AndroidDriver driver) {
        this.driver = driver;
    }

    public AsymmetricEncryptionFragment clickAsymmetricEncryption() {
        waitUntilDisplayed();
        driver.findElement(AppiumBy.id("asymmetric")).click();
        return new AsymmetricEncryptionFragment(driver).waitUntilDisplayed();
    }

    public SymmetricEncryptionFragment clickSymmetricEncryption() {
        waitUntilDisplayed();
        driver.findElement(AppiumBy.id("symmetric")).click();
        return new SymmetricEncryptionFragment(driver).waitUntilDisplayed();
    }

    public SymmetricEncryptionWithPasswordFragment clickSymmetricEncryptionWithPassword() {
        waitUntilDisplayed();
        driver.findElement(AppiumBy.id("encryptionWithPassword")).click();
        return new SymmetricEncryptionWithPasswordFragment(driver).waitUntilDisplayed();
    }

    public AuthenticationFragment clickAuthentication() {
        waitUntilDisplayed();
        driver.findElement(AppiumBy.id("biometry")).click();
        return new AuthenticationFragment(driver).waitUntilDisplayed();
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public MainTabsFragment waitUntilDisplayed() {
        FragmentHelper.waitUntilDisplayed(driver, AppiumBy.id("biometry"));
        return this;
    }
}
