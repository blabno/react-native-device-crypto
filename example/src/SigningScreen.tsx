import * as React from 'react';

import {
    SafeAreaView,
    ScrollView,
    View,
    Text,
    Button,
    TextInput
} from 'react-native';
import {Dropdown} from 'react-native-element-dropdown';
import DeviceCrypto, {
    AccessLevel
} from 'react-native-device-crypto';
import SwitchBox from './components/SwitchBox';
import styles from './styles';
import type {FC} from "react";
import {useCallback, useEffect} from "react";
import CopiableText from "./components/CopiableText";

export const accessLevelOptions = [
    {label: 'Always', value: 0},
    {label: 'Unlocked device', value: 1},
    {label: 'Authentication required', value: 2}
];

const SigningScreen: FC = () => {
    const [error, setError] = React.useState<string>('');
    const [signature, setSignature] = React.useState<string>('');
    const [textToBeSigned, setTextToBeSigned] =
        React.useState<string>('text to be signed');
    const [publicKey, setPublicKey] = React.useState<string>('');
    const [alias, setAlias] = React.useState<string>('signing');
    const [accessLevel, setAccessLevel] = React.useState<AccessLevel>(0);
    const [invalidateOnNewBiometry, setInvalidateOnNewBiometry] =
        React.useState<boolean>(false);
    const [isKeyExists, setIsKeyExists] = React.useState<boolean>(false);
    const [showSignature, setShowSignature] = React.useState<boolean>(false);

    const handleError = useCallback((err: unknown) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        setError((err as any).message);
    }, []);

    const createKey = useCallback(async () => {
        try {
            const res = await DeviceCrypto.getOrCreateSigningKey(alias, {
                accessLevel,
                invalidateOnNewBiometry
            });
            setPublicKey(res);
            setSignature('');
            setShowSignature(false);
        } catch (err) {
            handleError(err);
        }
    }, [accessLevel, alias, handleError, invalidateOnNewBiometry]);

    const sign = useCallback(async () => {
        try {
            setShowSignature(false);
            const res = await DeviceCrypto.sign(alias, textToBeSigned, {
                biometryTitle: 'Authenticate',
                biometrySubTitle: 'Signing',
                biometryDescription: 'Authenticate your self to sign the text'
            });
            setSignature(res);
            setShowSignature(true);
        } catch (err) {
            handleError(err);
        }
    }, [alias, handleError, textToBeSigned]);

    const deleteKey = useCallback(async () => {
        try {
            await DeviceCrypto.deleteKey(alias);
            const res = await DeviceCrypto.isKeyExists(alias);
            setIsKeyExists(res);
            setShowSignature(false);
        } catch (err) {
            handleError(err);
        }
    }, [alias, handleError]);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const setAccessLevelFromDropdown = useCallback((item: any) => setAccessLevel(item.value), []);

    useEffect(() => {
        DeviceCrypto.isKeyExists(alias).then(
            (exist: boolean) => {
                setIsKeyExists(exist);
                if (exist) {
                    DeviceCrypto.getPublicKeyPEM(alias).then(setPublicKey);
                }
            }
        );
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
                    onChange={setAccessLevelFromDropdown}
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
                        <Text>Text to be signed</Text>
                        <TextInput
                            style={styles.input}
                            onChangeText={setTextToBeSigned}
                            value={textToBeSigned}/>
                        <Button onPress={sign} title="Sign the text" color="#841584"/>
                    </React.Fragment>
                ) : null}

                {showSignature ? (
                    <React.Fragment>
                        <Text>Signature</Text>
                        <CopiableText text={signature}/>
                    </React.Fragment>
                ) : null}

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

export default SigningScreen;
