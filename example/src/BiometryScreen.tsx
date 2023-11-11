import * as React from 'react';

import {SafeAreaView, ScrollView, View, Text, Button} from 'react-native';
// eslint-disable-next-line import/no-unresolved
import DeviceCrypto from 'react-native-device-crypto';
import styles from './styles';
import type {FC} from "react";
import {useCallback, useState} from "react";
import {testID} from "./util";

const BiometryScreen: FC = () => {
  const [error, setError] = useState(false);
  const [status, setStatus] = React.useState<string | undefined>();

  const setSuccessMessage = useCallback((msg: string) => {
    setError(false);
    setStatus(msg);
  }, []);

  const setErrorMessage = useCallback((msg: string) => {
    setError(true);
    setStatus(msg);
  }, []);

  const handleError = useCallback((err: unknown) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setErrorMessage((err as any).message);
  }, [setErrorMessage]);

  const clear = useCallback(() => setStatus(undefined), []);

  const simpleAuthentication = useCallback(async () => {
    try {
      clear();
      await DeviceCrypto.authenticateWithBiometry({
        biometryDescription: 'Biometric Prompt Description',
        biometrySubTitle: 'Biometric Prompt Sub Title',
        biometryTitle: 'Biometric Prompt Title'
      });
      setSuccessMessage('Authentication successful');
    } catch (err) {
      handleError(err);
    }
  }, [clear, handleError]);

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView>
        <Text>Confirm with biometry</Text>
        <Button
          onPress={simpleAuthentication}
          title="Fire Biometric Authentication"
          color="#841584"
          testID={testID('authenticateButton')}/>
        <View style={styles.separator}/>
        <Button
          onPress={clear}
          title="Clear"
          testID={testID('clearButton')}/>
        <View style={styles.separator}/>
        {status && <Text testID={testID('status')} style={error ? styles.errorBox : styles.infoBox}>{status}</Text>}
      </ScrollView>
    </SafeAreaView>
  );
};

export default BiometryScreen;
