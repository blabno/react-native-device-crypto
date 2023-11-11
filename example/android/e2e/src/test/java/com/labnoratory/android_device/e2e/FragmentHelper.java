package com.labnoratory.android_device.e2e;

import org.hamcrest.Matcher;
import org.openqa.selenium.By;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;
import java.util.function.Function;

import io.appium.java_client.AppiumBy;
import io.appium.java_client.android.AndroidDriver;

import static com.labnoratory.android_device.e2e.E2EHelper.PACKAGE_NAME;
import static org.hamcrest.MatcherAssert.assertThat;

public class FragmentHelper {

    public static void assertText(WebDriver driver, By selector, Matcher<String> matcher) {
        assertText(driver, selector, matcher, "");
    }

    public static void assertText(WebDriver driver, By selector, Matcher<String> matcher, String errorMessage) {
        assertText(driver, webDriver -> webDriver.findElement(selector), matcher, errorMessage);
    }

    public static void assertText(WebDriver driver, Function<WebDriver, WebElement> getElement, Matcher<String> matcher) {
        assertText(driver, getElement, matcher, "");
    }

    public static void assertText(WebDriver driver, Function<WebDriver, WebElement> getElement, Matcher<String> matcher, String errorMessage) {
        try {
            new WebDriverWait(driver, Duration.ofSeconds(1))
                    .until(webDriver -> {
                        try {
                            String text = getElement.apply(webDriver).getText();
                            return matcher.matches(text);
                        } catch (Exception ignore) {
                            return false;
                        }
                    });
        } catch (TimeoutException ignore) {
            assertThat(errorMessage, getElement.apply(driver).getText(), matcher);
        }
    }

    public static By byId(String id) {
        String uiautomatorText = String.format("new UiScrollable(new UiSelector().scrollable(true).instance(0)).scrollIntoView(new UiSelector().resourceId(\"%s\").instance(0))", resourceId(id));
        return AppiumBy.androidUIAutomator(uiautomatorText);
    }

    public static By byText(String text) {
        return By.xpath(String.format(".//*[@text=\"%s\"]", text));
    }

    public static String resourceId(String id) {
        return String.format("%s:id/%s", PACKAGE_NAME, id);
    }

    public static void setText(WebElement element, CharSequence... text) {
        element.clear();
        element.sendKeys(text);
    }

    public static boolean isDisplayed(WebDriver driver, By selector) {
        return !driver.findElements(selector).isEmpty();
    }

    public static void waitUntilDisappears(WebDriver driver, By selector) {
        new WebDriverWait(driver, Duration.ofSeconds(1))
                .until(webDriver -> !isDisplayed(webDriver, selector));
    }

    public static void waitUntilDisplayed(AndroidDriver driver, By selector) {
        new WebDriverWait(driver, Duration.ofSeconds(2))
                .until(webDriver -> isDisplayed(webDriver, selector));
    }
}