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

export interface LargeBytesAsymmetricEncryptionResult {
  cipherText: string,
  encryptedPassword: string,
  salt: string,
  initializationVector: string,
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
   * Signs the given text with given private key
   *
   * @param {String} plainText Text to be signed
   * @return {Promise} Resolves to signature in `Base64` when successful
   */
  async sign(
    alias: string,
    plainText: string,
    options: BiometryParams
  ): Promise<string> {
    return RNDeviceCrypto.sign(alias, plainText, options);
  },

  async encryptAsymmetrically(
    publicKey: string,
    plainText: string
  ): Promise<string> {
    return RNDeviceCrypto.encryptAsymmetrically(publicKey, plainText);
  },

  async encryptLargeBytesAsymmetrically(
    publicKey: string,
    plainText: string
  ): Promise<LargeBytesAsymmetricEncryptionResult> {
    return RNDeviceCrypto.encryptLargeBytesAsymmetrically(publicKey, plainText);
  },

  async decryptLargeBytesAsymmetrically(alias: string, encryptedData: LargeBytesAsymmetricEncryptionResult, options: BiometryParams): Promise<string> {
    const {encryptedPassword, salt, cipherText, initializationVector} = encryptedData;
    return RNDeviceCrypto.decryptLargeBytesAsymmetrically(alias, cipherText, encryptedPassword, salt, initializationVector, options);
  },

  async decryptAsymmetrically(alias: string, cipherText: string, options: BiometryParams): Promise<string> {
    return RNDeviceCrypto.decryptAsymmetrically(alias, cipherText, options);
  },

  /**
   * Encrypt the given text
   *
   * @param {String} base64bytesToEncrypt Text to be encrypted
   * @return {Promise} Resolves to encrypted text `Base64` formatted
   */
  async encryptSymmetrically(
    alias: string,
    base64bytesToEncrypt: string,
    options: BiometryParams
  ): Promise<EncryptionResult> {
    return RNDeviceCrypto.encryptSymmetrically(alias, base64bytesToEncrypt, options);
  },

  /**
   * Decrypt the encrypted text with given IV
   *
   * @param {String} plainText Text to be signed
   * @param {String} iv Base64 formatted IV
   * @return {Promise} Resolves to decrypted text when successful
   */
  async decryptSymmetrically(
    alias: string,
    plainText: string,
    iv: string,
    options: BiometryParams
  ): Promise<string> {
    return RNDeviceCrypto.decryptSymmetrically(alias, plainText, iv, options);
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
