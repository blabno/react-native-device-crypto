package com.labnoratory.android_device.e2e;

import com.github.javafaker.Faker;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.LinkedList;

import io.appium.java_client.android.AndroidDriver;

import static com.labnoratory.android_device.e2e.Random.getUnique;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.emptyString;
import static org.testng.Assert.assertNotEquals;

public class SymmetricEncryptionE2ETest {

    @BeforeMethod
    public void setUp() {
        SymmetricEncryptionFragment encryptionTab = new MainTabsFragment(AndroidDriverFactory.getInstance())
                .clickSymmetricEncryption();
        if (encryptionTab.isKeyAvailable()) {
            encryptionTab.removeKey();
        }
    }

    @Test
    public void encryptSymmetrically___key_does_not_require_authentication() {
        LinkedList<String> inputs = getUnique(2, () -> Faker.instance().backToTheFuture().quote());
        String input1 = inputs.pop();
        String input2 = inputs.pop();
        AndroidDriver driver = AndroidDriverFactory.getInstance();
        SymmetricEncryptionFragment encryptionTab = new SymmetricEncryptionFragment(driver)
                .assureKeyDoesNotRequireAuthentication()
                .createKey()
                .assertStatus(is(equalTo("Encryption key created successfully")))
                .setInput(input1)
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .setInput("")
                .assertCipherText(is(not(emptyString())))
                .assertIV(is(not(emptyString())));
        String cipherText = encryptionTab.getCipherText();
        String iv = encryptionTab.getIv();
        encryptionTab
                .clickDecryptButton()
                .assertStatus(is(equalTo("Data decrypted successfully")))
                .assertDecryptedData(is(equalTo(input1)))
                .setInput(input2)
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")));
        assertNotEquals(cipherText, encryptionTab.getCipherText());
        assertNotEquals(iv, encryptionTab.getIv());

        encryptionTab.removeKey()
                .createKey()
                .setCipherText(cipherText)
                .setIv(iv)
                .clickDecryptButton()
                .assertStatus(is(equalTo("Failed to decrypt with symmetric key")));
    }

    @Test
    public void encryptSymmetrically___key_requires_authentication() {
        LinkedList<String> inputs = getUnique(2, () -> Faker.instance().backToTheFuture().quote());
        String input1 = inputs.pop();
        String input2 = inputs.pop();
        AndroidDriver driver = AndroidDriverFactory.getInstance();
        SymmetricEncryptionFragment encryptionTab = new SymmetricEncryptionFragment(driver)
                .assureKeyRequiresAuthentication()
                .createKey()
                .assertStatus(is(equalTo("Encryption key created successfully")))
                .setInput(input1)
                .clickEncryptButton()
                .assertBiometricPromptDisplayed()
                .scanEnrolledFinger()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .setInput("")
                .assertCipherText(is(not(emptyString())))
                .assertIV(is(not(emptyString())));
        String cipherText = encryptionTab.getCipherText();
        String iv = encryptionTab.getIv();
        encryptionTab.clickDecryptButton()
                .assertBiometricPromptDisplayed()
                .scanEnrolledFinger()
                .assertStatus(is(equalTo("Data decrypted successfully")))
                .assertDecryptedData(is(equalTo(input1)))
                .setInput(input2)
                .clickEncryptButton()
                .scanEnrolledFinger()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .assertCipherText(is(not(equalTo(cipherText))))
                .assertIV(is(not(equalTo(iv))));

        encryptionTab.removeKey()
                .createKey()
                .setCipherText(cipherText)
                .setIv(iv)
                .clickDecryptButton()
                .scanEnrolledFinger()
                .assertStatus(is(equalTo("Failed to decrypt with symmetric key")));
    }
}