package com.reactnativedevicecrypto.test;

public class RejectedPromiseException extends Throwable {
  private Object[] args;

  public RejectedPromiseException(Object[] args) {
    this.args = args;
  }
}
