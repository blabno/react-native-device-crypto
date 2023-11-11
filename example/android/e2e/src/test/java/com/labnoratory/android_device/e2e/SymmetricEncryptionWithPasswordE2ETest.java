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

public class SymmetricEncryptionWithPasswordE2ETest {
    @BeforeMethod
    public void setUp() {
        AndroidDriver driver = AndroidDriverFactory.getInstance();
        SymmetricEncryptionWithPasswordFragment encryptionTab = new MainTabsFragment(driver)
                .clickSymmetricEncryptionWithPassword();

        encryptionTab.setInput("")
                .setPassword("")
                .setSalt("")
                .setIterations("")
                .setCipherText("")
                .setIv("");
    }

    @Test
    public void encryptSymmetricallyWithPassword() {
        Faker faker = Faker.instance();
        LinkedList<String> inputs = getUnique(2, () -> faker.chuckNorris().fact());
        String input1 = inputs.pop();
        String input2 = inputs.pop();
        AndroidDriver driver = AndroidDriverFactory.getInstance();
        String failedToDecryptMessage = "Failed to decrypt with password";
        String dataEncryptedSuccessfully = "Data encrypted successfully";

        inputs = getUnique(4, () -> faker.cat().name());
        String password = inputs.pop();
        String wrongPassword = inputs.pop();
        String salt = inputs.pop();
        String wrongSalt = inputs.pop();
        int rawIterations = faker.number().numberBetween(1, 1000);
        String iterations = "" + rawIterations;
        String wrongIterations = (rawIterations + 1) + "";
        SymmetricEncryptionWithPasswordFragment encryptionTab = new SymmetricEncryptionWithPasswordFragment(driver)
                .setInput(input1)
                .setPassword(password)
                .setSalt(salt)
                .setIterations(iterations)
                .clickEncryptButton()
                .assertStatus(is(equalTo(dataEncryptedSuccessfully)))
                .setInput("")
                .assertCipherText(is(not(emptyString())))
                .assertIV(is(not(emptyString())));
        String cipherText = encryptionTab.getCipherText();
        String iv = encryptionTab.getIv();
        encryptionTab
                .clickDecryptButton()
                .assertStatus(is(equalTo("Data decrypted successfully")))
                .assertDecryptedData(is(equalTo(input1)));
        encryptionTab
                .setInput(input2)
                .clickEncryptButton()
                .assertStatus(is(equalTo(dataEncryptedSuccessfully)));
        assertNotEquals(cipherText, encryptionTab.getCipherText());
        assertNotEquals(iv, encryptionTab.getIv());

        encryptionTab.setPassword(wrongPassword)
                .clickDecryptButton()
                .assertStatus(is(equalTo(failedToDecryptMessage)));

        encryptionTab.setPassword(password)
                .setSalt(wrongSalt)
                .clickDecryptButton()
                .assertStatus(is(equalTo(failedToDecryptMessage)));

        encryptionTab.setSalt(salt)
                .setIterations(wrongIterations)
                .clickDecryptButton()
                .assertStatus(is(equalTo(failedToDecryptMessage)));

        encryptionTab
                .setIterations(iterations)
                .clickDecryptButton()
                .assertStatus(is(equalTo("Data decrypted successfully")))
                .assertDecryptedData(is(equalTo(input2)));
    }
}