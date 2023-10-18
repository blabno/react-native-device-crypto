import * as React from 'react';

import {
    SafeAreaView,
    ScrollView,
    View,
    Text,
    Button,
    Switch,
    TextInput
} from 'react-native';
import {Dropdown} from 'react-native-element-dropdown';
import DeviceCrypto, {
    AccessLevel,
    type LargeBytesAsymmetricEncryptionResult
} from 'react-native-device-crypto';
import SwitchBox from './components/SwitchBox';
import styles from './styles';
import {type FC, useCallback, useState} from 'react';
import base64 from 'base-64';
import utf8 from 'utf8';
import CopiableText from "./components/CopiableText";

export const accessLevelOptions = [
    {label: 'Always', value: 0},
    {label: 'Unlocked device', value: 1},
    {label: 'Authentication required', value: 2}
];

const AsymmetricEncryptionScreen: FC = () => {
    const [error, setError] = useState<string>();
    const [decryptedData, setDecryptedData] = useState<string>();
    const [encryptedLargeData, setEncryptedLargeData] =
        useState<LargeBytesAsymmetricEncryptionResult>();
    const [encryptedData, setEncryptedData] = useState<string>();
    const [textToBeEncrypted, setTextToBeEncrypted] =
        useState<string>('text to be encrypt');
    const [publicKey, setPublicKey] = useState<string>();
    const [alias, setAlias] = useState<string>('asymmetric-encryption');
    const [accessLevel, setAccessLevel] = useState<AccessLevel>(
        AccessLevel.ALWAYS
    );
    const [invalidateOnNewBiometry, setInvalidateOnNewBiometry] =
        useState<boolean>(false);
    const [largeBytes, setLargeBytes] = useState<boolean>(false);
    const [isKeyExists, setIsKeyExists] = useState<boolean>(false);

    const createKey = useCallback(async () => {
        try {
            const res = await DeviceCrypto.getOrCreateAsymmetricEncryptionKey(alias, {
                accessLevel,
                invalidateOnNewBiometry
            });
            setPublicKey(res);
            setEncryptedData(undefined);
            setDecryptedData(undefined);
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            setError(err.message);
        }
    }, [accessLevel, alias, invalidateOnNewBiometry]);

    const toggleLargeBytes = useCallback(
        () => setLargeBytes(prev => !prev),
        []
    );

    const encrypt = useCallback(async () => {
        try {
            setEncryptedData(undefined);
            setDecryptedData(undefined);
            const publicKeyDER = await DeviceCrypto.getPublicKeyDER(alias);
            const base64bytesToEncrypt = base64.encode(
                utf8.encode(textToBeEncrypted)
            );
            if (largeBytes) {
                const res = await DeviceCrypto.encryptLargeBytesAsymmetrically(
                    publicKeyDER,
                    base64bytesToEncrypt
                );
                setEncryptedLargeData(res);
            } else {
                const res = await DeviceCrypto.encryptAsymmetrically(
                    publicKeyDER,
                    base64bytesToEncrypt
                );
                setEncryptedData(res);
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            setError(err.message);
        }
    }, [alias, largeBytes, textToBeEncrypted]);

    const decrypt = useCallback(async () => {
        try {
            setDecryptedData(undefined);
            if (encryptedLargeData) {
                const res = await DeviceCrypto.decryptLargeBytesAsymmetrically(
                    alias,
                    encryptedLargeData,
                    {
                        biometryTitle: 'Authentication is required',
                        biometrySubTitle: 'Decryption',
                        biometryDescription:
                            'Authenticate your self to decrypt given data.'
                    }
                );
                setDecryptedData(utf8.decode(base64.decode(res)));
            } else if (encryptedData) {
                const res = await DeviceCrypto.decryptAsymmetrically(
                    alias,
                    encryptedData,
                    {
                        biometryTitle: 'Authentication is required',
                        biometrySubTitle: 'Decryption',
                        biometryDescription:
                            'Authenticate your self to decrypt given data.'
                    }
                );
                setDecryptedData(utf8.decode(base64.decode(res)));
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            setError(err.message);
        }
    }, [alias, encryptedData, encryptedLargeData]);

    const deleteKey = async () => {
        try {
            await DeviceCrypto.deleteKey(alias);
            const res = await DeviceCrypto.isKeyExists(alias);
            setIsKeyExists(res);
            setEncryptedData(undefined);
            setDecryptedData(undefined);
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            setError(err.message);
        }
    };

    React.useEffect(() => {
        DeviceCrypto.isKeyExists(alias).then((exist: boolean) => {
            setIsKeyExists(exist);
            if (exist) {
                DeviceCrypto.getPublicKeyPEM(alias).then(setPublicKey);
            }
        });
    }, [alias, isKeyExists, publicKey]);

    return (
        <SafeAreaView style={styles.container}>
            <ScrollView>
                {error ? (
                    <React.Fragment>
                        <View style={styles.errorBox}>
                            <Text>ERROR: {error}</Text>
                        </View>
                    </React.Fragment>
                ) : null}

                <Text>Key alias</Text>
                <TextInput style={styles.input} onChangeText={setAlias} value={alias}/>

                <Text>Key accessibility</Text>
                <Dropdown
                    data={accessLevelOptions}
                    search={false}
                    searchPlaceholder="Search"
                    labelField="label"
                    valueField="value"
                    placeholder="Select item"
                    value={accessLevel}
                    onChange={item => setAccessLevel(item.value)}
                    style={styles.dropdown}/>

                <SwitchBox
                    onChange={setInvalidateOnNewBiometry}
                    text="Invalidate key on new biometry/remove"/>
                <Button onPress={createKey} title="Create key" color="#841584"/>
                <Text style={styles.hint}>
                    That will create a new key or return public key of the existing key.
                </Text>

                {isKeyExists ? (
                    <React.Fragment>
                        <View style={styles.separator}/>
                        <Text>Public Key</Text>
                        <CopiableText style={styles.hint} text={publicKey}/>
                    </React.Fragment>
                ) : null}

                {isKeyExists ? (
                    <React.Fragment>
                        <View style={styles.separator}/>
                        <Text>Text to be encrypted</Text>
                        <TextInput
                            style={styles.input}
                            onChangeText={setTextToBeEncrypted}
                            value={textToBeEncrypted}/>
                        <View style={styles.largeBytes}>
                            <Text>Large bytes</Text>
                            <Switch value={largeBytes} onChange={toggleLargeBytes}/>
                        </View>
                        <Button
                            onPress={encrypt}
                            title="Encrypt the text"
                            color="#841584"/>
                    </React.Fragment>
                ) : null}

                {encryptedData || encryptedLargeData ? (
                    <React.Fragment>
                        <Text>Encrypted data</Text>
                        <CopiableText
                            text={JSON.stringify(
                                encryptedData || encryptedLargeData,
                                null,
                                2
                            )}/>
                        <Button
                            onPress={decrypt}
                            title="Decrypt the result"
                            color="#841584"/>
                    </React.Fragment>
                ) : null}

                {decryptedData && (
                    <React.Fragment>
                        <Text>Decrypted data</Text>
                        <CopiableText text={decryptedData}/>
                    </React.Fragment>
                )}

                {isKeyExists ? (
                    <React.Fragment>
                        <View style={styles.separator}/>
                        <Button
                            onPress={deleteKey}
                            title="Delete the key"
                            color="#841584"/>
                    </React.Fragment>
                ) : null}
            </ScrollView>
        </SafeAreaView>
    );
};

export default AsymmetricEncryptionScreen;
