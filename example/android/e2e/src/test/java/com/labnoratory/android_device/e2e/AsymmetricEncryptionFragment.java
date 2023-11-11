package com.labnoratory.android_device.e2e;

import org.hamcrest.Matcher;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;

import io.appium.java_client.android.AndroidDriver;

import static com.labnoratory.android_device.e2e.FragmentHelper.assertText;
import static com.labnoratory.android_device.e2e.FragmentHelper.byId;
import static com.labnoratory.android_device.e2e.FragmentHelper.byText;
import static com.labnoratory.android_device.e2e.FragmentHelper.isDisplayed;
import static com.labnoratory.android_device.e2e.FragmentHelper.setText;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class AsymmetricEncryptionFragment {

    private static class Selectors {
        private static final By accessLevel = byId("accessLevel");
        private static final By cipherText = byId("cipherText");
        private static final By createKeyButton = byId("createKeyButton");
        private static final By decryptButton = byId("decryptButton");
        private static final By decryptedData = byId("decryptedData");
        private static final By encryptButton = byId("encryptButton");
        private static final By input = byId("input");
        private static final By removeKeyButton = byId("removeKeyButton");
        private static final By status = byId("status");
    }

    private final AndroidDriver driver;
    private BiometricPromptFragment biometricPromptFragment;

    public AsymmetricEncryptionFragment(AndroidDriver driver) {
        this.driver = driver;
    }

    public AsymmetricEncryptionFragment assertCipherText(Matcher<String> matcher) {
        assertText(driver, Selectors.cipherText, matcher);
        return this;
    }

    public AsymmetricEncryptionFragment assertDecryptedData(Matcher<String> matcher) {
        assertText(driver, Selectors.decryptedData, matcher);
        return this;
    }

    public AsymmetricEncryptionFragment assertStatus(Matcher<String> matcher) {
        assertText(driver, Selectors.status, matcher);
        return this;
    }

    public AsymmetricEncryptionFragment assureKeyDoesNotRequireAuthentication() {
        String optionText = "Always";
        if (!driver.findElements(byText(optionText)).isEmpty()) {
            return this;
        }
        driver.findElement(Selectors.accessLevel).click();
        By optionSelector = byText(optionText);
        FragmentHelper.waitUntilDisplayed(driver, optionSelector);
        driver.findElement(optionSelector).click();
        return this;
    }

    public AsymmetricEncryptionFragment assureKeyRequiresAuthentication() {
        By authenticationRequired = byText("Authentication required");
        if (isDisplayed(driver, authenticationRequired)) {
            return this;
        }
        driver.findElement(Selectors.accessLevel).click();
        FragmentHelper.waitUntilDisplayed(driver, authenticationRequired);
        driver.findElement(authenticationRequired).click();
        return this;
    }

    public AsymmetricEncryptionFragment switchLargeBytesOff() {
        By largeBytesSelector = byId("largeBytes");
        WebElement largeBytes = driver.findElement(largeBytesSelector);
        String checked = largeBytes.getAttribute("checked");
        if (!"true".equals(checked)) {
            return this;
        }
        largeBytes.click();
        new WebDriverWait(driver, Duration.ofSeconds(2))
                .until(webDriver -> !"true".equals(driver.findElement(largeBytesSelector).getAttribute("checked")));
        return this;
    }

    public AsymmetricEncryptionFragment switchLargeBytesOn() {
        By largeBytesSelector = byId("largeBytes");
        WebElement largeBytes = driver.findElement(largeBytesSelector);
        String checked = largeBytes.getAttribute("checked");
        if ("true".equals(checked)) {
            return this;
        }
        largeBytes.click();
        new WebDriverWait(driver, Duration.ofSeconds(2))
                .until(webDriver -> "true".equals(driver.findElement(largeBytesSelector).getAttribute("checked")));
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public AsymmetricEncryptionFragment clickCreateKeyButton() {
        driver.findElement(Selectors.createKeyButton).click();
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public AsymmetricEncryptionFragment clickRemoveKeyButton() {
        driver.findElement(Selectors.removeKeyButton).click();
        return this;
    }

    public AsymmetricEncryptionFragment clickDecryptButton() {
        driver.findElement(Selectors.decryptButton).click();
        return this;
    }

    public AsymmetricEncryptionFragment clickEncryptButton() {
        driver.findElement(Selectors.encryptButton).click();
        return this;
    }

    public AsymmetricEncryptionFragment createKey() {
        return clickCreateKeyButton().assertStatus(is(equalTo("Encryption key created successfully")));
    }

    public String getCipherText() {
        return driver.findElement(Selectors.cipherText).getText();
    }

    public boolean isKeyAvailable() {
        return isDisplayed(driver, Selectors.removeKeyButton);
    }

    public AsymmetricEncryptionFragment removeKey() {
        return clickRemoveKeyButton().assertStatus(is(equalTo("Key removed successfully")));
    }

    public AsymmetricEncryptionFragment scanEnrolledFinger() {
        getBiometricPromptFragment()
                .waitUntilDisplayed()
                .scanEnrolledFinger();
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public AsymmetricEncryptionFragment setCipherText(CharSequence... text) {
        setText(driver.findElement(Selectors.cipherText), text);
        return this;
    }

    public AsymmetricEncryptionFragment setInput(CharSequence... text) {
        setText(driver.findElement(Selectors.input), text);
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public AsymmetricEncryptionFragment waitUntilDisplayed() {
        new NavBarFragment(driver).assertTitle(is(equalTo("Asymmetric")));
        return this;
    }

    private BiometricPromptFragment getBiometricPromptFragment() {
        if (null == biometricPromptFragment) {
            biometricPromptFragment = new BiometricPromptFragment(driver);
        }
        return biometricPromptFragment;
    }
}
