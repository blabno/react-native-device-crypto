package com.reactnativedevicecrypto;

import java.util.Map;
import java.util.Optional;


public class Helpers {

    public static String getString(Map<String, Object> options, String key, String defaultValue) {
        return Optional.ofNullable(options.get(key)).map(Object::toString).orElse(defaultValue);
    }

}
