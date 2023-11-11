package com.labnoratory.android_device.e2e;

import org.checkerframework.checker.nullness.qual.NonNull;
import org.openqa.selenium.By;

import io.appium.java_client.android.AndroidDriver;

import static com.labnoratory.android_device.e2e.E2EHelper.sleep;
import static com.labnoratory.android_device.e2e.FragmentHelper.byText;

public class BiometricPromptFragment {

    private By biometricAuthenticationLabel = byText("Biometric Prompt Title");

    private final AndroidDriver driver;

    public BiometricPromptFragment(AndroidDriver driver) {
        this.driver = driver;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public BiometricPromptFragment scanEnrolledFinger() {
        E2EHelper.scanEnrolledFinger();
        waitUntilDisappears();
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public BiometricPromptFragment scanUnknownFinger() {
        E2EHelper.scanUnknownFinger();
        sleep(1000);
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public BiometricPromptFragment cancel() {
        By cancelButtonSelector = byText("Cancel");
        driver.findElement(cancelButtonSelector).click();
        waitUntilDisappears();
        return this;
    }

    public BiometricPromptFragment waitUntilDisplayed() {
        return waitUntilDisplayed("Authentication is required");
    }

    public BiometricPromptFragment waitUntilDisplayed(@NonNull String title) {
        biometricAuthenticationLabel = byText(title);
        FragmentHelper.waitUntilDisplayed(driver, biometricAuthenticationLabel);
        return this;
    }

    /** @noinspection UnusedReturnValue*/
    public BiometricPromptFragment waitUntilDisappears() {
        FragmentHelper.waitUntilDisappears(driver, biometricAuthenticationLabel);
        return this;
    }
}
