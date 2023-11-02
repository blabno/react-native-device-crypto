import { NativeModules } from 'react-native';

const RNDeviceCrypto = NativeModules.DeviceCrypto;

export interface BiometryParams {
  biometryTitle: string;
  biometrySubTitle: string;
  biometryDescription: string;
}

export enum AccessLevel {
  ALWAYS = 0,
  UNLOCKED_DEVICE = 1,
  AUTHENTICATION_REQUIRED = 2,
}
export interface KeyCreationParams {
  accessLevel: AccessLevel;
  invalidateOnNewBiometry?: boolean;
}

export enum KeyTypes {
  SIGNING = 0,
  SYMMETRIC_ENCRYPTION = 1,
  ASYMMETRIC_ENCRYPTION = 2,
}

export interface EncryptionResult {
  initializationVector: string;
  cipherText: string;
}

export enum BiometryType {
  NONE = 'NONE',
  TOUCH = 'TOUCH',
  FACE = 'FACE',
  IRIS = 'IRIS',
}

export enum SecurityLevel {
  NOT_PROTECTED = 'NOT_PROTECTED',
  PIN_OR_PATTERN = 'PIN_OR_PATTERN',
  BIOMETRY = 'BIOMETRY',
}

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
  async getOrCreateSigningKey(
    alias: string,
    options: KeyCreationParams
  ): Promise<string> {
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
  async getOrCreateSymmetricEncryptionKey(
    alias: string,
    options: KeyCreationParams
  ): Promise<boolean> {
    return RNDeviceCrypto.createKey(alias, {
      ...options,
      keyType: KeyTypes.SYMMETRIC_ENCRYPTION
    });
  },

  async getOrCreateAsymmetricEncryptionKey(
    alias: string,
    options: KeyCreationParams
  ): Promise<string> {
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
  async deleteKey(alias: string): Promise<boolean> {
    return Boolean(RNDeviceCrypto.deleteKey(alias));
  },

  /**
   * Get the public key as PEM formatted
   *
   * @return {Promise} Resolves to a public key when successful
   */
  async getPublicKeyPEM(alias: string): Promise<string> {
    return RNDeviceCrypto.getPublicKeyPEM(alias);
  },

  /**
   * Get the public key in Base64 encoded DER format
   *
   * @return {Promise} Resolves to a public key when successful
   */
  async getPublicKeyDER(alias: string): Promise<string> {
    return RNDeviceCrypto.getPublicKeyDER(alias);
  },

  /**
   * Get random bytes Base64 encoded
   *
   * @return {Promise} Resolves base64 encoded bytes
   */
  async getRandomBytes(length: number): Promise<string> {
    return RNDeviceCrypto.getRandomBytes(length);
  },


  /**
   * Signs the given Base64 encoded bytes with given private key
   *
   * @param {String} payloadBase64 Text to be signed
   * @return {Promise} Resolves to signature in `Base64` when successful
   */
  async sign(
    alias: string,
    payloadBase64: string,
    options: BiometryParams
  ): Promise<string> {
    return RNDeviceCrypto.sign(alias, payloadBase64, options);
  },

  async encryptAsymmetrically(
    publicKeyDER: string,
    payloadBase64: string
  ): Promise<string> {
    return RNDeviceCrypto.encryptAsymmetrically(publicKeyDER, payloadBase64);
  },

  async decryptAsymmetrically(alias: string, cipherTextBase64: string, options: BiometryParams): Promise<string> {
    return RNDeviceCrypto.decryptAsymmetrically(alias, cipherTextBase64, options);
  },

  /**
   * Encrypt given Base64 encoded bytes
   *
   * @param {String} payloadBase64 data to be encrypted
   * @return {Promise} Resolves to encrypted text `Base64` formatted
   */
  async encryptSymmetrically(
    alias: string,
    payloadBase64: string,
    options: BiometryParams
  ): Promise<EncryptionResult> {
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
  async encryptSymmetricallyWithPasswordAndSalt(
    passwordBase64: string,
    saltBase64: string,
    iterations: number,
    payloadBase64: string
  ): Promise<EncryptionResult> {
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
  async decryptSymmetricallyWithPasswordAndSalt(
    passwordBase64: string,
    saltBase64: string,
    ivBase64: string,
    iterations: number,
    cipherTextBase64: string
  ): Promise<string> {
    return RNDeviceCrypto.decryptSymmetricallyWithPasswordAndSalt(passwordBase64, saltBase64, ivBase64, iterations, cipherTextBase64);
  },

  /**
   * Decrypt the encrypted text with given IV
   *
   * @param {String} cipherTextBase64 Text to be signed
   * @param {String} ivBase64 Base64 formatted IV
   * @return {Promise} Resolves to decrypted text when successful
   */
  async decryptSymmetrically(
    alias: string,
    cipherTextBase64: string,
    ivBase64: string,
    options: BiometryParams
  ): Promise<string> {
    return RNDeviceCrypto.decryptSymmetrically(alias, cipherTextBase64, ivBase64, options);
  },

  /**
   * Checks the key existence
   *
   * @return {Promise} Resolves to `true` if exists
   */
  async isKeyExists(alias: string): Promise<boolean> {
    return RNDeviceCrypto.isKeyExists(alias);
  },

  /**
   * Checks the biometry is enrolled on device
   *
   * @returns {Promise} Resolves `true` if biometry is enrolled on the device
   */
  async isBiometryEnrolled(): Promise<boolean> {
    return RNDeviceCrypto.isBiometryEnrolled();
  },

  /**
   * Checks the device security level
   *
   * @return {Promise} Resolves one of `SecurityLevel`
   */
  async deviceSecurityLevel(): Promise<SecurityLevel> {
    return RNDeviceCrypto.deviceSecurityLevel() as SecurityLevel;
  },

  /**
   * Returns biometry type already enrolled on the device
   *
   * @returns {Promise} Resolves `BiometryType`
   */
  async getBiometryType(): Promise<BiometryType> {
    return RNDeviceCrypto.getBiometryType() as BiometryType;
  },

  /**
   * Authenticate user with device biometry
   *
   * @returns {Promise} Resolves `true` if user passes biometry or fallback pin
   */
  async authenticateWithBiometry(options: BiometryParams): Promise<boolean> {
    return RNDeviceCrypto.authenticateWithBiometry(options);
  }
};

export default DeviceCrypto;
