import { NativeModules } from 'react-native';
const RNDeviceCrypto = NativeModules.DeviceCrypto;
export let AccessLevel;

(function (AccessLevel) {
  AccessLevel[AccessLevel["ALWAYS"] = 0] = "ALWAYS";
  AccessLevel[AccessLevel["UNLOCKED_DEVICE"] = 1] = "UNLOCKED_DEVICE";
  AccessLevel[AccessLevel["AUTHENTICATION_REQUIRED"] = 2] = "AUTHENTICATION_REQUIRED";
})(AccessLevel || (AccessLevel = {}));

export let KeyTypes;

(function (KeyTypes) {
  KeyTypes[KeyTypes["ASYMMETRIC"] = 0] = "ASYMMETRIC";
  KeyTypes[KeyTypes["SYMMETRIC"] = 1] = "SYMMETRIC";
  KeyTypes[KeyTypes["ASYMMETRIC_ENCRYPTION"] = 2] = "ASYMMETRIC_ENCRYPTION";
})(KeyTypes || (KeyTypes = {}));

export let BiometryType;

(function (BiometryType) {
  BiometryType["NONE"] = "NONE";
  BiometryType["TOUCH"] = "TOUCH";
  BiometryType["FACE"] = "FACE";
  BiometryType["IRIS"] = "IRIS";
})(BiometryType || (BiometryType = {}));

export let SecurityLevel;

(function (SecurityLevel) {
  SecurityLevel["NOT_PROTECTED"] = "NOT_PROTECTED";
  SecurityLevel["PIN_OR_PATTERN"] = "PIN_OR_PATTERN";
  SecurityLevel["BIOMETRY"] = "BIOMETRY";
})(SecurityLevel || (SecurityLevel = {}));

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
  async getOrCreateAsymmetricKey(alias, options) {
    return RNDeviceCrypto.createKey(alias, { ...options,
      keyType: KeyTypes.ASYMMETRIC
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
  async getOrCreateSymmetricKey(alias, options) {
    return RNDeviceCrypto.createKey(alias, { ...options,
      keyType: KeyTypes.SYMMETRIC
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
   * @return {Promise} Resolves to public key when successful
   */
  async getPublicKey(alias) {
    return RNDeviceCrypto.getPublicKey(alias);
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

  /**
   * Encrypt the given text
   *
   * @param {String} plainText Text to be encrypted
   * @return {Promise} Resolves to encrypted text `Base64` formatted
   */
  async encrypt(alias, plainText, options) {
    return RNDeviceCrypto.encrypt(alias, plainText, options);
  },

  /**
   * Decrypt the encrypted text with given IV
   *
   * @param {String} plainText Text to be signed
   * @param {String} iv Base64 formatted IV
   * @return {Promise} Resolves to decrypted text when successful
   */
  async decrypt(alias, plainText, iv, options) {
    return RNDeviceCrypto.decrypt(alias, plainText, iv, options);
  },

  /**
   * Checks the key existence
   *
   * @return {Promise} Resolves to `true` if exists
   */
  async isKeyExists(alias, keyType) {
    return RNDeviceCrypto.isKeyExists(alias, keyType);
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
    try {
      return RNDeviceCrypto.authenticateWithBiometry(options);
    } catch (err) {
      throw err;
    }
  }

};
export default DeviceCrypto;
//# sourceMappingURL=index.js.map