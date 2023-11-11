package com.labnoratory.android_device.e2e;

import com.github.javafaker.Faker;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.LinkedList;
import java.util.function.Supplier;

import io.appium.java_client.android.AndroidDriver;

import static com.labnoratory.android_device.e2e.Random.getUnique;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.matchesPattern;
import static org.testng.Assert.assertNotEquals;

public class AsymmetricEncryptionE2ETest {

    @BeforeMethod
    public void setUp() {
        AsymmetricEncryptionFragment encryptionTab = new MainTabsFragment(AndroidDriverFactory.getInstance())
                .clickAsymmetricEncryption();
        if (encryptionTab.isKeyAvailable()) {
            encryptionTab.removeKey();
        }
    }

    @Test
    public void encryptAsymmetrically___small_bytes_and_key_does_not_require_authentication() {
        LinkedList<String> inputs = getUnique(2, () -> Faker.instance().animal().name());
        String input1 = inputs.pop();
        String input2 = inputs.pop();
        AndroidDriver driver = AndroidDriverFactory.getInstance();
        AsymmetricEncryptionFragment encryptionTab = new AsymmetricEncryptionFragment(driver)
                .assureKeyDoesNotRequireAuthentication()
                .createKey()
                .assertStatus(is(equalTo("Encryption key created successfully")))
                .setInput(input1)
                .setCipherText("")
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .setInput("")
                .assertCipherText(is(not(emptyString())));
        String cipherText = encryptionTab.getCipherText();
        encryptionTab
                .clickDecryptButton()
                .assertStatus(is(equalTo("Data decrypted successfully")))
                .assertDecryptedData(is(equalTo(input1)))
                .setInput(input2)
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .assertCipherText(is(not(equalTo(cipherText))));

        encryptionTab.removeKey()
                .createKey()
                .setCipherText(cipherText)
                .clickDecryptButton()
                .assertStatus(is(equalTo("Failed to decrypt with asymmetric key")));
    }

    @Test
    public void encryptAsymmetrically___small_bytes_and_key_requires_authentication() {
        LinkedList<String> inputs = getUnique(2, () -> Faker.instance().backToTheFuture().character());
        String input1 = inputs.pop();
        String input2 = inputs.pop();
        AndroidDriver driver = AndroidDriverFactory.getInstance();
        AsymmetricEncryptionFragment encryptionTab = new AsymmetricEncryptionFragment(driver)
                .assureKeyRequiresAuthentication()
                .createKey()
                .assertStatus(is(equalTo("Encryption key created successfully")))
                .setInput(input1)
                .setCipherText("")
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .setInput("")
                .assertCipherText(is(not(emptyString())));
        String cipherText = encryptionTab.getCipherText();
        encryptionTab
                .clickDecryptButton()
                .scanEnrolledFinger()
                .assertStatus(is(equalTo("Data decrypted successfully")))
                .setInput(input2)
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .assertCipherText(is(not(equalTo(cipherText))));

        encryptionTab.removeKey()
                .createKey()
                .setCipherText(cipherText)
                .clickDecryptButton()
                .scanEnrolledFinger()
                .assertStatus(is(equalTo("Failed to decrypt with asymmetric key")));
    }

    @Test
    public void encryptAsymmetrically___large_bytes_and_key_does_not_require_authentication() {
        Faker faker = Faker.instance();
        String input1 = concat(10, () -> faker.backToTheFuture().quote());
        String input2 = concat(11, () -> faker.backToTheFuture().quote());
        assertNotEquals(input1, input2);
        AndroidDriver driver = AndroidDriverFactory.getInstance();
        AsymmetricEncryptionFragment encryptionTab = new AsymmetricEncryptionFragment(driver)
                .assureKeyDoesNotRequireAuthentication()
                .createKey()
                .assertStatus(is(equalTo("Encryption key created successfully")))
                .switchLargeBytesOff()
                .setInput(input1)
                .setCipherText("")
                .clickEncryptButton()
                .assertStatus(matchesPattern(".*input must be under 256 bytes.*"))
                .switchLargeBytesOn()
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .setInput("")
                .assertCipherText(is(not(emptyString())));
        String cipherText = encryptionTab.getCipherText();
        encryptionTab
                .clickDecryptButton()
                .assertStatus(is(equalTo("Data decrypted successfully")))
                .assertDecryptedData(is(equalTo(input1)))
                .setInput(input2)
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .assertCipherText(is(not(equalTo(cipherText))));

        encryptionTab.removeKey()
                .createKey()
                .setCipherText(cipherText)
                .clickDecryptButton()
                .assertStatus(is(equalTo("Failed to decrypt with asymmetric key")));
    }

    @Test
    public void encryptAsymmetrically___large_bytes_and_key_requires_authentication() {
        Faker faker = Faker.instance();
        String input1 = concat(10, () -> faker.backToTheFuture().quote());
        String input2 = concat(11, () -> faker.backToTheFuture().quote());
        assertNotEquals(input1, input2);
        AndroidDriver driver = AndroidDriverFactory.getInstance();
        AsymmetricEncryptionFragment encryptionTab = new AsymmetricEncryptionFragment(driver)
                .assureKeyRequiresAuthentication()
                .createKey()
                .assertStatus(is(equalTo("Encryption key created successfully")))
                .switchLargeBytesOff()
                .setInput(input1)
                .setCipherText("")
                .clickEncryptButton()
                .assertStatus(matchesPattern(".*input must be under 256 bytes.*"))
                .switchLargeBytesOn()
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .setInput("")
                .assertCipherText(is(not(emptyString())));
        String cipherText = encryptionTab.getCipherText();
        encryptionTab
                .clickDecryptButton()
                .scanEnrolledFinger()
                .assertStatus(is(equalTo("Data decrypted successfully")))
                .assertDecryptedData(is(equalTo(input1)))
                .setInput(input2)
                .clickEncryptButton()
                .assertStatus(is(equalTo("Data encrypted successfully")))
                .assertCipherText(is(not(equalTo(cipherText))));

        encryptionTab.removeKey()
                .createKey()
                .setCipherText(cipherText)
                .clickDecryptButton()
                .scanEnrolledFinger()
                .assertStatus(is(equalTo("Failed to decrypt with asymmetric key")));
    }


    private static String concat(int i, Supplier<String> s) {
        StringBuilder builder = new StringBuilder();
        for (int j = 0; j < i; j++) {
            builder.append(s.get()).append(" ");
        }
        return builder.toString().trim();
    }
}
