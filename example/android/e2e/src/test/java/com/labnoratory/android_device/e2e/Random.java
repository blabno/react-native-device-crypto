package com.labnoratory.android_device.e2e;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.function.Supplier;

public class Random {

    public static LinkedList<String> getUnique(int size, Supplier<String> supplier) {
        Set<String> result = new HashSet<>();
        int iterations = 0;
        while (result.size() < size) {
            if (iterations++ > 100) {
                throw new RuntimeException("Failed to get unique value in 100 attempts");
            }
            if (result.add(supplier.get())) {
                iterations = 0;
            }
        }
        return new LinkedList<>(result);
    }

}
