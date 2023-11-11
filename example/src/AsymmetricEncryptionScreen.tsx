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
import DeviceCrypto, {AccessLevel} from 'react-native-device-crypto';
import SwitchBox from './components/SwitchBox';
import styles from './styles';
import {type FC, useCallback, useEffect, useState} from 'react';
import base64 from 'base-64';
import utf8 from 'utf8';
import CopiableText from "./components/CopiableText";
import {testID} from "./util";

export interface AsymmetricallyEncryptedLargeData {
  cipherText: string,
  encryptedPassword: string,
  iterations: number,
  salt: string,
  initializationVector: string,
}

export const accessLevelOptions = [
  {label: 'Always', value: 0},
  {label: 'Unlocked device', value: 1},
  {label: 'Authentication required', value: 2}
];

const AsymmetricEncryptionScreen: FC = () => {
  const [error, setError] = useState(false);
  const [status, setStatus] = useState<string>();
  const [decryptedData, setDecryptedData] = useState<string>();
  const [encryptedLargeData, setEncryptedLargeData] =
    useState<AsymmetricallyEncryptedLargeData>();
  const [encryptedData, setEncryptedData] = useState<string>();
  const [cipherText, setCipherText] = useState<string>();
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

  const setSuccessMessage = useCallback((msg: string) => {
    setError(false);
    setStatus(msg);
  }, []);

  const setErrorMessage = useCallback((msg: string) => {
    setError(true);
    setStatus(msg);
  }, []);

  const createKey = useCallback(async () => {
    try {
      setStatus(undefined);
      const res = await DeviceCrypto.getOrCreateAsymmetricEncryptionKey(alias, {
        accessLevel,
        invalidateOnNewBiometry
      });
      setPublicKey(res);
      setEncryptedData(undefined);
      setDecryptedData(undefined);
      setSuccessMessage('Encryption key created successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, [accessLevel, alias, invalidateOnNewBiometry]);

  const toggleLargeBytes = useCallback(() => setLargeBytes(prev => !prev), []);

  const encrypt = useCallback(async () => {
    try {
      setStatus(undefined);
      setEncryptedData(undefined);
      setDecryptedData(undefined);
      const publicKeyDER = await DeviceCrypto.getPublicKeyDER(alias);
      const base64bytesToEncrypt = base64.encode(
        utf8.encode(textToBeEncrypted)
      );
      if (largeBytes) {
        const password = await DeviceCrypto.getRandomBytes(190);
        const salt = await DeviceCrypto.getRandomBytes(190);
        const encryptedPassword = await DeviceCrypto.encryptAsymmetrically(publicKeyDER, password);
        const iterations = 1024;
        const {cipherText, initializationVector} = await DeviceCrypto.encryptSymmetricallyWithPassword(password, salt, iterations, base64bytesToEncrypt);
        const result: AsymmetricallyEncryptedLargeData = {
          cipherText,
          encryptedPassword,
          iterations,
          initializationVector,
          salt
        };
        setEncryptedLargeData(result);
      } else {
        const res = await DeviceCrypto.encryptAsymmetrically(
          publicKeyDER,
          base64bytesToEncrypt
        );
        setEncryptedData(res);
      }
      setSuccessMessage('Data encrypted successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, [alias, largeBytes, textToBeEncrypted]);

  const decrypt = useCallback(async () => {
    try {
      setStatus(undefined);
      setDecryptedData(undefined);
      const options = {
        biometryTitle: 'Authentication is required',
        biometrySubTitle: 'Decryption',
        biometryDescription: 'Authenticate your self to decrypt given data.'
      };
      if (largeBytes) {
        const encryptedLargeData = JSON.parse(cipherText || '');
        const {encryptedPassword, salt, iterations, initializationVector} = JSON.parse(cipherText || '');
        const password = await DeviceCrypto.decryptAsymmetrically(alias, encryptedPassword, options);
        const res = await DeviceCrypto.decryptSymmetricallyWithPassword(password, salt, initializationVector, iterations, encryptedLargeData.cipherText);
        setDecryptedData(utf8.decode(base64.decode(res)));
      } else if (cipherText) {
        const res = await DeviceCrypto.decryptAsymmetrically(
          alias,
          cipherText,
          options
        );
        setDecryptedData(utf8.decode(base64.decode(res)));
      }
      setSuccessMessage('Data decrypted successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, [alias, cipherText, largeBytes]);

  const deleteKey = useCallback(async () => {
    try {
      setStatus(undefined);
      await DeviceCrypto.deleteKey(alias);
      setIsKeyExists(await DeviceCrypto.isKeyExists(alias));
      setEncryptedData(undefined);
      setDecryptedData(undefined);
      setCipherText(undefined);
      setSuccessMessage('Key removed successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, []);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const setAccessLevelFromDropdown = useCallback((item: any) => setAccessLevel(item.value), []);


  useEffect(() => {
    if (encryptedData)
      setCipherText(encryptedData)
    else if (encryptedLargeData)
      setCipherText(JSON.stringify(encryptedLargeData, null, 2))
  }, [encryptedData, encryptedLargeData]);


  useEffect(() => {
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
        {status && (<Text testID={testID('status')} style={error ? styles.errorBox : styles.infoBox}>{status}</Text>)}

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
          testID={testID('accessLevel')}
          style={styles.dropdown}/>

        <SwitchBox
          onChange={setInvalidateOnNewBiometry}
          text="Invalidate key on new biometry/remove"/>
        <Button onPress={createKey} title="Create key" color="#841584" testID={testID('createKeyButton')}/>
        <Text style={styles.hint}>
          That will create a new key or return public key of the existing key.
        </Text>

        {isKeyExists && (
          <>
            <View style={styles.separator}/>
            <Text>Public Key</Text>
            <CopiableText style={styles.hint} text={publicKey} testID={testID('publicKey')}/>
            <View style={styles.separator}/>
            <Text>Text to be encrypted</Text>
            <TextInput
              style={styles.input}
              onChangeText={setTextToBeEncrypted}
              multiline={true}
              numberOfLines={10}
              value={textToBeEncrypted}
              testID={testID('input')}/>
            <View style={styles.largeBytes}>
              <Text>Large bytes</Text>
              <Switch value={largeBytes} onChange={toggleLargeBytes} testID={testID('largeBytes')}/>
            </View>
            <Button
              onPress={encrypt}
              title="Encrypt the text"
              color="#841584"
              testID={testID('encryptButton')}/>
            <Text>Encrypted data</Text>
            <TextInput
              style={styles.input}
              multiline
              numberOfLines={10}
              onChangeText={setCipherText}
              value={cipherText}
              testID={testID('cipherText')}/>
            <Button
              onPress={decrypt}
              title="Decrypt the result"
              color="#841584"
              testID={testID('decryptButton')}/>
            {decryptedData && (
              <>
                <Text>Decrypted data</Text>
                <CopiableText text={decryptedData} testID={testID('decryptedData')}/>
              </>
            )}
            <View style={styles.separator}/>
            <Button
              onPress={deleteKey}
              title="Delete the key"
              color="#841584"
              testID={testID('removeKeyButton')}/>
          </>
        )}
      </ScrollView>
    </SafeAreaView>
  );
};

export default AsymmetricEncryptionScreen;
