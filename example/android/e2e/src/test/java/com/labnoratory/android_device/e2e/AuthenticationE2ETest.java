package com.labnoratory.android_device.e2e;

import org.testng.annotations.Test;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class AuthenticationE2ETest {

    @Test
    public void authenticate___authentication_succeeds() {
        new MainTabsFragment(AndroidDriverFactory.getInstance())
                .clickAuthentication()
                .waitUntilDisplayed()
                .clickClearButton()
                .clickAuthenticateButton()
                .scanUnknownFinger()
                .scanEnrolledFinger()
                .assertStatus(is(equalTo("Authentication successful")));
    }

    @Test
    public void authenticate___authentication_cancelled() {
        new MainTabsFragment(AndroidDriverFactory.getInstance())
                .clickAuthentication()
                .waitUntilDisplayed()
                .clickClearButton()
                .clickAuthenticateButton()
                .cancelBiometricAuthentication()
                .assertStatus(is(equalTo("Failed to authenticate with biometry")));
    }

}