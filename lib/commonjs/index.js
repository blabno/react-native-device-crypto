"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = exports.SecurityLevel = exports.KeyTypes = exports.BiometryType = exports.AccessLevel = void 0;
var _reactNative = require("react-native");
const RNDeviceCrypto = _reactNative.NativeModules.DeviceCrypto;
let AccessLevel = exports.AccessLevel = /*#__PURE__*/function (AccessLevel) {
  AccessLevel[AccessLevel["ALWAYS"] = 0] = "ALWAYS";
  AccessLevel[AccessLevel["UNLOCKED_DEVICE"] = 1] = "UNLOCKED_DEVICE";
  AccessLevel[AccessLevel["AUTHENTICATION_REQUIRED"] = 2] = "AUTHENTICATION_REQUIRED";
  return AccessLevel;
}({});
let KeyTypes = exports.KeyTypes = /*#__PURE__*/function (KeyTypes) {
  KeyTypes[KeyTypes["SIGNING"] = 0] = "SIGNING";
  KeyTypes[KeyTypes["SYMMETRIC_ENCRYPTION"] = 1] = "SYMMETRIC_ENCRYPTION";
  KeyTypes[KeyTypes["ASYMMETRIC_ENCRYPTION"] = 2] = "ASYMMETRIC_ENCRYPTION";
  return KeyTypes;
}({});
let BiometryType = exports.BiometryType = /*#__PURE__*/function (BiometryType) {
  BiometryType["NONE"] = "NONE";
  BiometryType["TOUCH"] = "TOUCH";
  BiometryType["FACE"] = "FACE";
  BiometryType["IRIS"] = "IRIS";
  return BiometryType;
}({});
let SecurityLevel = exports.SecurityLevel = /*#__PURE__*/function (SecurityLevel) {
  SecurityLevel["NOT_PROTECTED"] = "NOT_PROTECTED";
  SecurityLevel["PIN_OR_PATTERN"] = "PIN_OR_PATTERN";
  SecurityLevel["BIOMETRY"] = "BIOMETRY";
  return SecurityLevel;
}({});
const DeviceCrypto = {
  /**
   * Create public/private key pair inside the secure hardware or get the existing public key
   * Secure enclave/TEE/StrongBox
   *
   * Cryptography algorithms
   * EC secp256k1 on iOS
   * EC secp256r1 on Android
   *
   * @return {Promise} Resolves to public key when successful
   */
  async getOrCreateSigningKey(alias, options) {
    return RNDeviceCrypto.createKey(alias, {
      ...options,
      keyType: KeyTypes.SIGNING
    });
  },
  /**
   * Create AES key inside the secure hardware. Returns `true` if the key already exists.
   * Secure enclave/TEE/StrongBox
   *
   * Cryptography algorithms AES256
   *
   * @return {Promise} Resolves to `true` when successful
   */
  async getOrCreateSymmetricEncryptionKey(alias, options) {
    return RNDeviceCrypto.createKey(alias, {
      ...options,
      keyType: KeyTypes.SYMMETRIC_ENCRYPTION
    });
  },
  async getOrCreateAsymmetricEncryptionKey(alias, options) {
    return RNDeviceCrypto.createKey(alias, {
      ...options,
      keyType: KeyTypes.ASYMMETRIC_ENCRYPTION
    });
  },
  /**
   * Delete the key from secure hardware
   *
   * @return {Promise} Resolves to `true` when successful
   */
  async deleteKey(alias) {
    return Boolean(RNDeviceCrypto.deleteKey(alias));
  },
  /**
   * Get the public key as PEM formatted
   *
   * @return {Promise} Resolves to a public key when successful
   */
  async getPublicKeyPEM(alias) {
    return RNDeviceCrypto.getPublicKeyPEM(alias);
  },
  /**
   * Get the public key in Base64 encoded DER format
   *
   * @return {Promise} Resolves to a public key when successful
   */
  async getPublicKeyDER(alias) {
    return RNDeviceCrypto.getPublicKeyDER(alias);
  },
  /**
   * Signs the given text with given private key
   *
   * @param {String} plainText Text to be signed
   * @return {Promise} Resolves to signature in `Base64` when successful
   */
  async sign(alias, plainText, options) {
    return RNDeviceCrypto.sign(alias, plainText, options);
  },
  async encryptAsymmetrically(publicKey, plainText) {
    return RNDeviceCrypto.encryptAsymmetrically(publicKey, plainText);
  },
  async encryptLargeBytesAsymmetrically(publicKey, plainText) {
    return RNDeviceCrypto.encryptLargeBytesAsymmetrically(publicKey, plainText);
  },
  async decryptLargeBytesAsymmetrically(alias, encryptedData, options) {
    const {
      encryptedPassword,
      salt,
      cipherText,
      initializationVector
    } = encryptedData;
    return RNDeviceCrypto.decryptLargeBytesAsymmetrically(alias, cipherText, encryptedPassword, salt, initializationVector, options);
  },
  async decryptAsymmetrically(alias, cipherText, options) {
    return RNDeviceCrypto.decryptAsymmetrically(alias, cipherText, options);
  },
  /**
   * Encrypt the given text
   *
   * @param {String} base64bytesToEncrypt Text to be encrypted
   * @return {Promise} Resolves to encrypted text `Base64` formatted
   */
  async encryptSymmetrically(alias, base64bytesToEncrypt, options) {
    return RNDeviceCrypto.encryptSymmetrically(alias, base64bytesToEncrypt, options);
  },
  /**
   * Decrypt the encrypted text with given IV
   *
   * @param {String} plainText Text to be signed
   * @param {String} iv Base64 formatted IV
   * @return {Promise} Resolves to decrypted text when successful
   */
  async decryptSymmetrically(alias, plainText, iv, options) {
    return RNDeviceCrypto.decryptSymmetrically(alias, plainText, iv, options);
  },
  /**
   * Checks the key existence
   *
   * @return {Promise} Resolves to `true` if exists
   */
  async isKeyExists(alias) {
    return RNDeviceCrypto.isKeyExists(alias);
  },
  /**
   * Checks the biometry is enrolled on device
   *
   * @returns {Promise} Resolves `true` if biometry is enrolled on the device
   */
  async isBiometryEnrolled() {
    return RNDeviceCrypto.isBiometryEnrolled();
  },
  /**
   * Checks the device security level
   *
   * @return {Promise} Resolves one of `SecurityLevel`
   */
  async deviceSecurityLevel() {
    return RNDeviceCrypto.deviceSecurityLevel();
  },
  /**
   * Returns biometry type already enrolled on the device
   *
   * @returns {Promise} Resolves `BiometryType`
   */
  async getBiometryType() {
    return RNDeviceCrypto.getBiometryType();
  },
  /**
   * Authenticate user with device biometry
   *
   * @returns {Promise} Resolves `true` if user passes biometry or fallback pin
   */
  async authenticateWithBiometry(options) {
    return RNDeviceCrypto.authenticateWithBiometry(options);
  }
};
var _default = exports.default = DeviceCrypto;
//# sourceMappingURL=index.js.map