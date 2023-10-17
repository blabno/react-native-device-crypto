package io.phoenix_legacy.crypto;

import java.util.Random;

import static com.reactnativedevicecrypto.CryptoTests.toBase64;

public class Randoms {

    private static final Random random = new Random();

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    public static String randomString(int length) {
        return toBase64(randomBytes(length));
    }
}
