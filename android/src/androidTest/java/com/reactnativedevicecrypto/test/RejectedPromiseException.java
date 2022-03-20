package com.reactnativedevicecrypto.test;

import java.util.Arrays;

public class RejectedPromiseException extends Throwable {
    private final Object[] args;

    public RejectedPromiseException(Object[] args) {
        this.args = args;
    }

    @Override
    public String toString() {
        return "RejectedPromiseException{" +
                "args=" + Arrays.toString(args) +
                '}';
    }
}
