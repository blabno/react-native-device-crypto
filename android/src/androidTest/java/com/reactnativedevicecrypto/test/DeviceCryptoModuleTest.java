package com.reactnativedevicecrypto.test;

import android.app.Activity;

import com.facebook.react.bridge.JavaOnlyMap;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.PromiseImpl;
import com.facebook.react.bridge.ReactApplicationContext;
import com.reactnativedevicecrypto.DeviceCryptoModule;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

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

    CompletableFuture<Object[]> future2 = new CompletableFuture<>();
    deviceCryptoModule.createKey(keyName1, new JavaOnlyMap(), toPromise(future2));
    Object[] result1b = future2.get(1000, TimeUnit.SECONDS);
    assertEquals(1, result1b.length);
    assertTrue(result1b[0] instanceof String);
    assertEquals(result1[0], result1b[0]);

    CompletableFuture<Object[]> future3 = new CompletableFuture<>();
    String keyName2 = uniqueKeyName("anotherSigning");
    deviceCryptoModule.createKey(keyName2, new JavaOnlyMap(), toPromise(future3));
    Object[] result2 = future3.get(1000, TimeUnit.SECONDS);
    assertEquals(1, result2.length);
    assertTrue(result2[0] instanceof String);
    assertNotEquals(result1[0], result2[0]);
  }

  private static Promise toPromise(CompletableFuture<Object[]> future) {
    return new PromiseImpl(future::complete, args -> future.completeExceptionally(new RejectedPromiseException(args)));
  }

  private String uniqueKeyName(String prefix) {
    return String.format("%s-%d-%d", prefix, System.currentTimeMillis(), keyCounter++);
  }
}
