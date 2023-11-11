package com.labnoratory.android_device.e2e;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;
import java.util.List;

import io.appium.java_client.android.AndroidDriver;
import io.appium.java_client.android.nativekey.AndroidKey;
import io.appium.java_client.android.nativekey.KeyEvent;

import static com.labnoratory.android_device.e2e.E2EHelper.PACKAGE_NAME;
import static com.labnoratory.android_device.e2e.E2EHelper.adbShell;
import static com.labnoratory.android_device.e2e.E2EHelper.emulateBackButton;
import static com.labnoratory.android_device.e2e.E2EHelper.scanEnrolledFinger;
import static com.labnoratory.android_device.e2e.E2EHelper.sleep;
import static com.labnoratory.android_device.e2e.FragmentHelper.byText;
import static com.labnoratory.android_device.e2e.FragmentHelper.setText;
import static com.labnoratory.android_device.e2e.FragmentHelper.waitUntilDisappears;
import static com.labnoratory.android_device.e2e.FragmentHelper.waitUntilDisplayed;

public class SecuritySettingsFragment {

    private static class Selectors {
        private static final By addFingerprintButton = byText("Add fingerprint");
        private static final By deleteButton = By.id("com.android.settings:id/delete_button");
        private static final By deviceSecurityLabel = byText("DEVICE SECURITY");
        private static final By doneButton = byText("DONE");
        private static final By pinEntry = By.id("com.android.settings:id/password_entry");
    }

    private final AndroidDriver driver;

    public static WebElement getDeleteConfirmButton(WebDriver driver) {
        List<WebElement> elements = driver.findElements(byText("Yes, remove"));
        if (elements.isEmpty()) elements = driver.findElements(byText("Delete"));
        return elements.get(0);
    }

    public static void setupFingerprint(AndroidDriver driver) {
        String pin = "1111";
        adbShell("locksettings clear --old " + pin);
        sleep(500);
        adbShell("locksettings set-pin " + pin);
        sleep(500);
        SecuritySettingsFragment settingsFragment = new SecuritySettingsFragment(driver)
                .open()
                .clickFingerprintMenuItem()
                .enterPIN(pin);
        if (settingsFragment.hasFingersEnrolled()) {
            settingsFragment.removeFingers()
                    .clickAddFingerprintButton();
        } else {
            settingsFragment.clickNext();
        }
        settingsFragment
                .scanFingerprint()
                .clickDone();
        adbShell(String.format("am start %s/.MainActivity", PACKAGE_NAME));
        sleep(1000);
    }

    public SecuritySettingsFragment(AndroidDriver driver) {
        this.driver = driver;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public SecuritySettingsFragment clickAddFingerprintButton() {
        driver.findElement(Selectors.addFingerprintButton).click();
        waitUntilDisappears(driver, Selectors.addFingerprintButton);
        return this;
    }

    public SecuritySettingsFragment clickFingerprintMenuItem() {
        driver.findElement(byText("Fingerprint")).click();
        waitUntilDisplayed(driver, byText("Re-enter your PIN"));
        return this;
    }

    public SecuritySettingsFragment enterPIN(CharSequence... text) {
        setText(driver.findElement(Selectors.pinEntry), text);
        driver.pressKey(new KeyEvent(AndroidKey.ENTER));
        waitUntilDisappears(driver, Selectors.pinEntry);
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public SecuritySettingsFragment clickNext() {
        driver.findElement(byText("NEXT")).click();
        waitUntilDisplayed(driver, byText("Touch the sensor"));
        return this;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public SecuritySettingsFragment clickDone() {
        driver.findElement(Selectors.doneButton).click();
        waitUntilDisappears(driver, Selectors.doneButton);
        return this;
    }

    public boolean hasFingersEnrolled() {
        return !driver.findElements(Selectors.deleteButton).isEmpty();
    }

    public SecuritySettingsFragment open() {
        adbShell("am start -a android.settings.SECURITY_SETTINGS");
        int i = 0;
        while (driver.findElements(Selectors.deviceSecurityLabel).isEmpty()) {
            emulateBackButton();
            sleep(500);
            if (i++ > 10) throw new RuntimeException("Failed to open security settings");
        }
        return this;
    }

    public SecuritySettingsFragment removeFingers() {
        while (hasFingersEnrolled()) {
            int initialDeleteButtonsCount = driver.findElements(Selectors.deleteButton).size();
            driver.findElement(Selectors.deleteButton).click();
            getDeleteConfirmButton(driver).click();
            new WebDriverWait(driver, Duration.ofSeconds(1))
                    .until(webDriver -> initialDeleteButtonsCount != driver.findElements(Selectors.deleteButton).size());
        }
        return this;
    }

    public SecuritySettingsFragment scanFingerprint() {
        for (int i = 0; i < 3; i++) {
            scanEnrolledFinger();
            sleep(500);
        }
        waitUntilDisplayed(driver, Selectors.doneButton);
        return this;
    }
}
