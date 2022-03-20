package com.reactnativedevicecrypto.test;

import android.app.Activity;
import android.util.Base64;

import com.facebook.react.bridge.JavaOnlyMap;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.PromiseImpl;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableMap;
import com.reactnativedevicecrypto.DeviceCryptoModule;
import com.reactnativedevicecrypto.Helpers;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import androidx.test.ext.junit.rules.ActivityScenarioRule;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class DeviceCryptoModuleTest {

  private DeviceCryptoModule deviceCryptoModule;

  private int keyCounter;

  @Rule
  public ActivityScenarioRule<TestActivity> activityRule = new ActivityScenarioRule<>(TestActivity.class);

  @Before
  public void setUp() throws Exception {
    CompletableFuture<Activity> future = new CompletableFuture<>();
    activityRule.getScenario().onActivity(future::complete);
    Activity activity = future.get(1000, TimeUnit.SECONDS);
    deviceCryptoModule = new DeviceCryptoModule(new ReactApplicationContext(activity));
  }

  @Test
  public void createKey() throws Exception {
    CompletableFuture<Object[]> future1 = new CompletableFuture<>();
    String keyName1 = uniqueKeyName("signing");
    deviceCryptoModule.createKey(keyName1, new JavaOnlyMap(), toPromise(future1));
    Object[] result1 = future1.get(1000, TimeUnit.SECONDS);
    assertEquals(1, result1.length);
    assertTrue(result1[0] instanceof String);

    assertEquals(result1[0], createKey(keyName1));

    String keyName2 = uniqueKeyName("anotherSigning");
    assertNotEquals(result1[0], createKey(keyName2));
  }

  @Test
  public void getPublicKeyBytes() throws Exception {
    String keyName1 = uniqueKeyName("signing");
    createAsymmetricEncryptionKey(keyName1);
    String keyName2 = uniqueKeyName("encryption");
    createAsymmetricEncryptionKey(keyName2);

    CompletableFuture<Object[]> future1 = new CompletableFuture<>();
    deviceCryptoModule.getPublicKeyBytes(keyName1, toPromise(future1));
    Object[] result1 = future1.get(1000, TimeUnit.SECONDS);
    assertEquals(1, result1.length);
    assertTrue(result1[0] instanceof String);
    assertEquals(result1[0], Base64.encodeToString(Base64.decode(result1[0].toString(), Base64.NO_WRAP), Base64.NO_WRAP));

    assertEquals(result1[0], getPublicKeyBytes(keyName1));
    assertNotEquals(result1[0], getPublicKeyBytes(keyName2));
  }

  private String createKey(String alias) throws ExecutionException, InterruptedException, TimeoutException {
    return createKey(alias, new JavaOnlyMap());
  }

  private String createAsymmetricEncryptionKey(String alias) throws ExecutionException, InterruptedException, TimeoutException {
    JavaOnlyMap options = new JavaOnlyMap();
    options.putInt("keyType", Helpers.KeyType.ASYMMETRIC_ENCRYPTION);
    return createKey(alias, options);
  }

  private String createKey(String alias, ReadableMap options) throws ExecutionException, InterruptedException, TimeoutException {
    return execute(promise -> deviceCryptoModule.createKey(alias, options, promise), new StringConverter());
  }

  private String getPublicKeyBytes(String alias) throws ExecutionException, InterruptedException, TimeoutException {
    return execute(promise -> deviceCryptoModule.getPublicKeyBytes(alias, promise), new StringConverter());
  }

  private <T> T execute(PromiseExecutor executor, Converter<T> converter) throws ExecutionException, InterruptedException, TimeoutException {
    CompletableFuture<Object[]> future = new CompletableFuture<>();
    executor.execute(toPromise(future));
    Object[] objects = future.get(1000, TimeUnit.SECONDS);
    return converter.convert(objects);
  }

  private static Promise toPromise(CompletableFuture<Object[]> future) {
    return new PromiseImpl(future::complete, args -> future.completeExceptionally(new RejectedPromiseException(args)));
  }

  private String uniqueKeyName(String prefix) {
    return String.format("%s-%d-%d", prefix, System.currentTimeMillis(), keyCounter++);
  }

  public interface PromiseExecutor {
    void execute(Promise promise);
  }

  public interface Converter<T> {
    T convert(Object[] args);
  }

  public static class StringConverter implements Converter<String> {
    @Override
    public String convert(Object[] args) {
      return null == args[0] ? null : args[0].toString();
    }
  }
}
