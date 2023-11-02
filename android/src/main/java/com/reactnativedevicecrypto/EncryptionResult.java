package com.reactnativedevicecrypto;

import java.util.Arrays;

import androidx.annotation.NonNull;

public class EncryptionResult {
    public byte[] initializationVector;
    public byte[] cipherText;

    public EncryptionResult(byte[] cipherText, byte[] initializationVector) {
        this.cipherText = cipherText;
        this.initializationVector = initializationVector;
    }

    @NonNull
    @Override
    public String toString() {
        return "EncryptionResult{" +
                "initializationVector=" + Arrays.toString(initializationVector) +
                ", cipherText=" + Arrays.toString(cipherText) +
                '}';
    }
}
