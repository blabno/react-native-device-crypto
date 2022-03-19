package com.reactnativedevicecrypto;

public class AuthenticationErrorException extends RuntimeException {
  private final int errorCode;
  private final CharSequence errString;

  public AuthenticationErrorException(int errorCode, CharSequence errString) {
    this.errorCode = errorCode;
    this.errString = errString;
  }

  public int getErrorCode() {
    return errorCode;
  }

  public CharSequence getErrString() {
    return errString;
  }

  @Override
  public String toString() {
    return "AuthenticationErrorException{" +
      "errorCode=" + errorCode +
      ", errString=" + errString +
      '}';
  }
}
