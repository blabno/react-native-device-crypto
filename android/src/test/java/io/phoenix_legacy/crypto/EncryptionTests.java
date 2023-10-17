package io.phoenix_legacy.crypto;


import com.reactnativedevicecrypto.CryptoTests;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.Security;

import static io.phoenix_legacy.crypto.Randoms.randomBytes;
import static io.phoenix_legacy.crypto.Randoms.randomString;
import static io.phoenix_legacy.crypto.TestCrypto.decrypt;
import static io.phoenix_legacy.crypto.TestCrypto.encryptBytesAsymmetrically;
import static io.phoenix_legacy.crypto.TestCrypto.encryptSymmetrically;
import static org.junit.Assert.assertArrayEquals;

public class EncryptionTests {

    @BeforeClass
    public static void beforeClass() {
        if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    @Test
    public void decryptLargeBytesAsymmetrically() throws Exception {
        SimpleEncryption encryption = new SimpleEncryption();
        String keyAlias = randomString(10);
        KeyPair keyPair = encryption.generateKeyPair(keyAlias);

        byte[] password = randomBytes(190);
        byte[] salt = randomBytes(190);
        byte[] bytesToEncrypt = randomBytes(1025 * 10);

        CryptoTests.EncryptionResult symmetricEncryptionResult = encryptSymmetrically(bytesToEncrypt, password, salt);
        byte[] cipherText = symmetricEncryptionResult.cipherText;
        byte[] decrypted = decrypt(cipherText, password, salt, symmetricEncryptionResult.initializationVector);
        assertArrayEquals(bytesToEncrypt,decrypted);

        byte[] encryptedPassword = encryptBytesAsymmetrically(keyPair.getPublic(), password);

        AbstractEncryption.AsymmetricallyEncryptedData encryptedData = new AbstractEncryption.AsymmetricallyEncryptedData(cipherText, encryptedPassword, salt, symmetricEncryptionResult.initializationVector);

        byte[] decryptedBytes = encryption.decryptLargeBytesAsymmetrically(keyAlias, encryptedData);

        assertArrayEquals(bytesToEncrypt, decryptedBytes);
    }

    @Test
    public void encryptLargeBytesAsymmetrically() throws Exception {
        SimpleEncryption encryption = new SimpleEncryption();
        String keyAlias = randomString(10);
        KeyPair keyPair = encryption.generateKeyPair(keyAlias);

        byte[] bytesToEncrypt = randomBytes(1025 * 11);

        AbstractEncryption.AsymmetricallyEncryptedData encryptedData = encryption.encryptLargeBytesAsymmetrically(bytesToEncrypt, keyPair.getPublic().getEncoded());

        byte[] password = decrypt(encryptedData.getEncryptedPassword(), keyPair);
        byte[] decryptedBytes = decrypt(encryptedData.getCipherText(), password, encryptedData.getSalt(), encryptedData.getIv());

        assertArrayEquals(bytesToEncrypt, decryptedBytes);
    }
}
