import * as React from 'react';

import {SafeAreaView, ScrollView, View, Text, Button} from 'react-native';
// eslint-disable-next-line import/no-unresolved
import DeviceCrypto from 'react-native-device-crypto';
import styles from './styles';
import type {FC} from "react";
import {useCallback} from "react";

const BiometryScreen: FC = () => {
    const [error, setError] = React.useState<string | undefined>('');
    const [isAuthenticated, setIsAuthenticated] = React.useState<boolean>();

    const handleError = useCallback((err: unknown) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        setError((err as any).message);
    }, []);

    const simpleAuthentication = useCallback(async () => {
        try {
            const res = await DeviceCrypto.authenticateWithBiometry({
                biometryDescription: 'Description',
                biometrySubTitle: 'Sub title',
                biometryTitle: ' Title'
            });
            setIsAuthenticated(res);
            setError('');
        } catch (err) {
            handleError(err);
            setIsAuthenticated(false);
        }
    }, [handleError]);

    return (
        <SafeAreaView style={styles.container}>
            <ScrollView>
                <Text>Confirm with biometry</Text>
                <Button
                    onPress={simpleAuthentication}
                    title="Fire Biometric Authentication"
                    color="#841584"/>

                {isAuthenticated ? (
                    <Text style={styles.positive}>SUCCESS</Text>
                ) : (
                    <Text style={styles.negative}>FAILED</Text>
                )}

                {error ? (
                    <React.Fragment>
                        <View style={styles.errorBox}>
                            <Text>ERROR: {error}</Text>
                        </View>
                    </React.Fragment>
                ) : null}
            </ScrollView>
        </SafeAreaView>
    );
};

export default BiometryScreen;
