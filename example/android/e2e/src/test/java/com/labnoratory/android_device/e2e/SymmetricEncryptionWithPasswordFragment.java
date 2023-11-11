package com.labnoratory.android_device.e2e;

import org.hamcrest.Matcher;
import org.openqa.selenium.By;

import io.appium.java_client.android.AndroidDriver;

import static com.labnoratory.android_device.e2e.FragmentHelper.assertText;
import static com.labnoratory.android_device.e2e.FragmentHelper.byId;
import static com.labnoratory.android_device.e2e.FragmentHelper.setText;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class SymmetricEncryptionWithPasswordFragment {

    private static class Selectors {
        private static final By cipherText = byId("cipherText");
        private static final By decryptButton = byId("decryptButton");
        private static final By decryptedData = byId("decryptedData");
        private static final By encryptButton = byId("encryptButton");
        private static final By input = byId("input");
        private static final By iterations = byId("iterations");
        private static final By iv = byId("iv");
        private static final By password = byId("password");
        private static final By salt = byId("salt");
        private static final By status = byId("status");
    }

    private final AndroidDriver driver;

    public SymmetricEncryptionWithPasswordFragment(AndroidDriver driver) {
        this.driver = driver;
    }

    public SymmetricEncryptionWithPasswordFragment assertCipherText(Matcher<String> matcher) {
        assertText(driver, SymmetricEncryptionWithPasswordFragment.Selectors.cipherText, matcher);
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public SymmetricEncryptionWithPasswordFragment assertDecryptedData(Matcher<String> matcher) {
        assertText(driver, SymmetricEncryptionWithPasswordFragment.Selectors.decryptedData, matcher);
        return this;
    }

    public SymmetricEncryptionWithPasswordFragment assertIV(Matcher<String> matcher) {
        assertText(driver, SymmetricEncryptionWithPasswordFragment.Selectors.iv, matcher);
        return this;
    }

    public SymmetricEncryptionWithPasswordFragment assertStatus(Matcher<String> matcher) {
        assertText(driver, Selectors.status, matcher);
        return this;
    }

    public SymmetricEncryptionWithPasswordFragment clickDecryptButton() {
        driver.findElement(Selectors.decryptButton).click();
        return this;
    }

    public SymmetricEncryptionWithPasswordFragment clickEncryptButton() {
        driver.findElement(Selectors.encryptButton).click();
        return this;
    }

    public String getCipherText() {
        return driver.findElement(Selectors.cipherText).getText();
    }

    public String getIv() {
        return driver.findElement(Selectors.iv).getText();
    }

    public SymmetricEncryptionWithPasswordFragment setCipherText(CharSequence... text) {
        setText(driver.findElement(Selectors.cipherText), text);
        return this;
    }

    public SymmetricEncryptionWithPasswordFragment setInput(CharSequence... text) {
        setText(driver.findElement(Selectors.input), text);
        return this;
    }

    public SymmetricEncryptionWithPasswordFragment setIterations(CharSequence... text) {
        setText(driver.findElement(Selectors.iterations), text);
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public SymmetricEncryptionWithPasswordFragment setIv(CharSequence... text) {
        setText(driver.findElement(Selectors.iv), text);
        return this;
    }

    public SymmetricEncryptionWithPasswordFragment setPassword(CharSequence... text) {
        setText(driver.findElement(Selectors.password), text);
        return this;
    }

    public SymmetricEncryptionWithPasswordFragment setSalt(CharSequence... text) {
        setText(driver.findElement(Selectors.salt), text);
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public SymmetricEncryptionWithPasswordFragment waitUntilDisplayed() {
        new NavBarFragment(driver).assertTitle(is(equalTo("With Password")));
        return this;
    }
}
