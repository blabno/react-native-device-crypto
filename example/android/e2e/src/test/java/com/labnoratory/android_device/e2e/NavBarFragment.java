package com.labnoratory.android_device.e2e;

import org.hamcrest.Matcher;
import org.openqa.selenium.By;

import io.appium.java_client.android.AndroidDriver;

import static com.labnoratory.android_device.e2e.FragmentHelper.assertText;
import static com.labnoratory.android_device.e2e.FragmentHelper.byId;

public class NavBarFragment {

    private static class Selectors {
        private static final By titleSelector = byId("title");
    }

    private final AndroidDriver driver;

    public NavBarFragment(AndroidDriver driver) {
        this.driver = driver;
    }

    /**
     * @noinspection UnusedReturnValue
     */
    public NavBarFragment assertTitle(Matcher<String> matcher) {
        assertText(driver, Selectors.titleSelector, matcher);
        return this;
    }
}
