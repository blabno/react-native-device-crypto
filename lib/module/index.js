import { NativeModules } from 'react-native';
const RNDeviceCrypto = NativeModules.DeviceCrypto;
export let AccessLevel = /*#__PURE__*/function (AccessLevel) {
  AccessLevel[AccessLevel["ALWAYS"] = 0] = "ALWAYS";
  AccessLevel[AccessLevel["UNLOCKED_DEVICE"] = 1] = "UNLOCKED_DEVICE";
  AccessLevel[AccessLevel["AUTHENTICATION_REQUIRED"] = 2] = "AUTHENTICATION_REQUIRED";
  return AccessLevel;
}({});
export let KeyTypes = /*#__PURE__*/function (KeyTypes) {
  KeyTypes[KeyTypes["SIGNING"] = 0] = "SIGNING";
  KeyTypes[KeyTypes["SYMMETRIC_ENCRYPTION"] = 1] = "SYMMETRIC_ENCRYPTION";
  KeyTypes[KeyTypes["ASYMMETRIC_ENCRYPTION"] = 2] = "ASYMMETRIC_ENCRYPTION";
  return KeyTypes;
}({});
export let BiometryType = /*#__PURE__*/function (BiometryType) {
  BiometryType["NONE"] = "NONE";
  BiometryType["TOUCH"] = "TOUCH";
  BiometryType["FACE"] = "FACE";
  BiometryType["IRIS"] = "IRIS";
  return BiometryType;
}({});
export let SecurityLevel = /*#__PURE__*/function (SecurityLevel) {
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
   * Get random bytes Base64 encoded
   *
   * @return {Promise} Resolves base64 encoded bytes
   */
  async getRandomBytes(length) {
    return RNDeviceCrypto.getRandomBytes(length);
  },
  /**
   * Signs the given Base64 encoded bytes with given private key
   *
   * @param {String} payloadBase64 Text to be signed
   * @return {Promise} Resolves to signature in `Base64` when successful
   */
  async sign(alias, payloadBase64, options) {
    return RNDeviceCrypto.sign(alias, payloadBase64, options);
  },
  async encryptAsymmetrically(publicKeyDER, payloadBase64) {
    return RNDeviceCrypto.encryptAsymmetrically(publicKeyDER, payloadBase64);
  },
  async decryptAsymmetrically(alias, cipherTextBase64, options) {
    return RNDeviceCrypto.decryptAsymmetrically(alias, cipherTextBase64, options);
  },
  /**
   * Encrypt given Base64 encoded bytes
   *
   * @param {String} payloadBase64 data to be encrypted
   * @return {Promise} Resolves to encrypted text `Base64` formatted
   */
  async encryptSymmetrically(alias, payloadBase64, options) {
    return RNDeviceCrypto.encryptSymmetrically(alias, payloadBase64, options);
  },
  /**
   * Encrypt given Base64 encoded bytes
   *
   * @param {String} passwordBase64 password used to derive encryption key
   * @param {String} saltBase64 salt used to derive encryption key
   * @param {number} iterations number of iterations used to derive encryption key
   * @param {String} payloadBase64 data to be encrypted
   * @return {Promise} Resolves to encrypted text `Base64` formatted
   */
  async encryptSymmetricallyWithPasswordAndSalt(passwordBase64, saltBase64, iterations, payloadBase64) {
    return RNDeviceCrypto.encryptSymmetricallyWithPasswordAndSalt(passwordBase64, saltBase64, iterations, payloadBase64);
  },
  /**
   * Decrypt given Base64 encoded bytes
   *
   * @param {String} passwordBase64 password used to derive encryption key
   * @param {String} saltBase64 salt used to derive encryption key
   * @param {String} ivBase64 initialization vector used to derive encryption key
   * @param {number} iterations number of iterations used to derive encryption key
   * @param {String} cipherTextBase64 data to be decrypted
   * @return {Promise} Resolves to decrypted text `Base64` formatted
   */
  async decryptSymmetricallyWithPasswordAndSalt(passwordBase64, saltBase64, ivBase64, iterations, cipherTextBase64) {
    return RNDeviceCrypto.decryptSymmetricallyWithPasswordAndSalt(passwordBase64, saltBase64, ivBase64, iterations, cipherTextBase64);
  },
  /**
   * Decrypt the encrypted text with given IV
   *
   * @param {String} cipherTextBase64 Text to be signed
   * @param {String} ivBase64 Base64 formatted IV
   * @return {Promise} Resolves to decrypted text when successful
   */
  async decryptSymmetrically(alias, cipherTextBase64, ivBase64, options) {
    return RNDeviceCrypto.decryptSymmetrically(alias, cipherTextBase64, ivBase64, options);
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
export default DeviceCrypto;
//# sourceMappingURL=index.js.map