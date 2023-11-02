export interface BiometryParams {
    biometryTitle: string;
    biometrySubTitle: string;
    biometryDescription: string;
}
export declare enum AccessLevel {
    ALWAYS = 0,
    UNLOCKED_DEVICE = 1,
    AUTHENTICATION_REQUIRED = 2
}
export interface KeyCreationParams {
    accessLevel: AccessLevel;
    invalidateOnNewBiometry?: boolean;
}
export declare enum KeyTypes {
    SIGNING = 0,
    SYMMETRIC_ENCRYPTION = 1,
    ASYMMETRIC_ENCRYPTION = 2
}
export interface EncryptionResult {
    initializationVector: string;
    cipherText: string;
}
export declare enum BiometryType {
    NONE = "NONE",
    TOUCH = "TOUCH",
    FACE = "FACE",
    IRIS = "IRIS"
}
export declare enum SecurityLevel {
    NOT_PROTECTED = "NOT_PROTECTED",
    PIN_OR_PATTERN = "PIN_OR_PATTERN",
    BIOMETRY = "BIOMETRY"
}
declare const DeviceCrypto: {
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
    getOrCreateSigningKey(alias: string, options: KeyCreationParams): Promise<string>;
    /**
     * Create AES key inside the secure hardware. Returns `true` if the key already exists.
     * Secure enclave/TEE/StrongBox
     *
     * Cryptography algorithms AES256
     *
     * @return {Promise} Resolves when successful
     */
    getOrCreateSymmetricEncryptionKey(alias: string, options: KeyCreationParams): Promise<void>;
    getOrCreateAsymmetricEncryptionKey(alias: string, options: KeyCreationParams): Promise<string>;
    /**
     * Delete the key from secure hardware
     *
     * @return {Promise} Resolves to `true` when successful
     */
    deleteKey(alias: string): Promise<boolean>;
    /**
     * Get the public key as PEM formatted
     *
     * @return {Promise} Resolves to a public key when successful
     */
    getPublicKeyPEM(alias: string): Promise<string>;
    /**
     * Get the public key in Base64 encoded DER format
     *
     * @return {Promise} Resolves to a public key when successful
     */
    getPublicKeyDER(alias: string): Promise<string>;
    /**
     * Get random bytes Base64 encoded
     *
     * @return {Promise} Resolves base64 encoded bytes
     */
    getRandomBytes(length: number): Promise<string>;
    /**
     * Signs the given Base64 encoded bytes with given private key
     *
     * @param {String} payloadBase64 Text to be signed
     * @return {Promise} Resolves to signature in `Base64` when successful
     */
    sign(alias: string, payloadBase64: string, options: BiometryParams): Promise<string>;
    encryptAsymmetrically(publicKeyDER: string, payloadBase64: string): Promise<string>;
    decryptAsymmetrically(alias: string, cipherTextBase64: string, options: BiometryParams): Promise<string>;
    /**
     * Encrypt given Base64 encoded bytes
     *
     * @param {String} payloadBase64 data to be encrypted
     * @return {Promise} Resolves to encrypted text `Base64` formatted
     */
    encryptSymmetrically(alias: string, payloadBase64: string, options: BiometryParams): Promise<EncryptionResult>;
    /**
     * Encrypt given Base64 encoded bytes
     *
     * @param {String} passwordBase64 password used to derive encryption key
     * @param {String} saltBase64 salt used to derive encryption key
     * @param {number} iterations number of iterations used to derive encryption key
     * @param {String} payloadBase64 data to be encrypted
     * @return {Promise} Resolves to encrypted text `Base64` formatted
     */
    encryptSymmetricallyWithPassword(passwordBase64: string, saltBase64: string, iterations: number, payloadBase64: string): Promise<EncryptionResult>;
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
    decryptSymmetricallyWithPassword(passwordBase64: string, saltBase64: string, ivBase64: string, iterations: number, cipherTextBase64: string): Promise<string>;
    /**
     * Decrypt the encrypted text with given IV
     *
     * @param {String} cipherTextBase64 Text to be signed
     * @param {String} ivBase64 Base64 formatted IV
     * @return {Promise} Resolves to decrypted text when successful
     */
    decryptSymmetrically(alias: string, cipherTextBase64: string, ivBase64: string, options: BiometryParams): Promise<string>;
    /**
     * Checks the key existence
     *
     * @return {Promise} Resolves to `true` if exists
     */
    isKeyExists(alias: string): Promise<boolean>;
    /**
     * Checks the biometry is enrolled on device
     *
     * @returns {Promise} Resolves `true` if biometry is enrolled on the device
     */
    isBiometryEnrolled(): Promise<boolean>;
    /**
     * Checks the device security level
     *
     * @return {Promise} Resolves one of `SecurityLevel`
     */
    deviceSecurityLevel(): Promise<SecurityLevel>;
    /**
     * Returns biometry type already enrolled on the device
     *
     * @returns {Promise} Resolves `BiometryType`
     */
    getBiometryType(): Promise<BiometryType>;
    /**
     * Authenticate user with device biometry
     *
     * @returns {Promise} that resolves if user passes biometry or fallback pin, rejects otherwise
     */
    authenticateWithBiometry(options: BiometryParams): Promise<void>;
};
export default DeviceCrypto;
//# sourceMappingURL=index.d.ts.map