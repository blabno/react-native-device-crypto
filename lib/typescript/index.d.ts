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
export interface AsymmetricallyEncryptedLargeData {
    cipherText: string;
    encryptedPassword: string;
    salt: string;
    initializationVector: string;
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
     * @return {Promise} Resolves to `true` when successful
     */
    getOrCreateSymmetricEncryptionKey(alias: string, options: KeyCreationParams): Promise<boolean>;
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
     * Signs the given text with given private key
     *
     * @param {String} plainText Text to be signed
     * @return {Promise} Resolves to signature in `Base64` when successful
     */
    sign(alias: string, plainText: string, options: BiometryParams): Promise<string>;
    encryptAsymmetrically(publicKey: string, plainText: string): Promise<string>;
    encryptLargeBytesAsymmetrically(publicKey: string, plainText: string): Promise<AsymmetricallyEncryptedLargeData>;
    decryptLargeBytesAsymmetrically(alias: string, encryptedData: AsymmetricallyEncryptedLargeData, options: BiometryParams): Promise<string>;
    decryptAsymmetrically(alias: string, cipherText: string, options: BiometryParams): Promise<string>;
    /**
     * Encrypt the given text
     *
     * @param {String} base64bytesToEncrypt Text to be encrypted
     * @return {Promise} Resolves to encrypted text `Base64` formatted
     */
    encryptSymmetrically(alias: string, base64bytesToEncrypt: string, options: BiometryParams): Promise<EncryptionResult>;
    /**
     * Decrypt the encrypted text with given IV
     *
     * @param {String} plainText Text to be signed
     * @param {String} iv Base64 formatted IV
     * @return {Promise} Resolves to decrypted text when successful
     */
    decryptSymmetrically(alias: string, plainText: string, iv: string, options: BiometryParams): Promise<string>;
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
     * @returns {Promise} Resolves `true` if user passes biometry or fallback pin
     */
    authenticateWithBiometry(options: BiometryParams): Promise<boolean>;
};
export default DeviceCrypto;
//# sourceMappingURL=index.d.ts.map