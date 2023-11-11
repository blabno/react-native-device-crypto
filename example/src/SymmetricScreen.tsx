import * as React from 'react';

import base64 from 'base-64';
import utf8 from 'utf8';
import {
  SafeAreaView,
  ScrollView,
  View,
  TextInput,
  Button,
  Text
} from 'react-native';
import {Dropdown} from 'react-native-element-dropdown';
import DeviceCrypto, {
  AccessLevel
} from 'react-native-device-crypto';
import SwitchBox from './components/SwitchBox';
import {accessLevelOptions} from './SigningScreen';
import styles from './styles';
import {useEffect, type FC, useCallback, useState} from "react";
import {testID} from "./util";
import CopiableText from "./components/CopiableText";

const SymmetricScreen: FC = () => {
  const [error, setError] = useState(false);
  const [status, setStatus] = useState<string>();
  const [isKeyExists, setIsKeyExists] = useState<boolean>(false);
  const [accessLevel, setAccessLevel] = useState<AccessLevel>(0);
  const [invalidateOnNewBiometry, setInvalidateOnNewBiometry] =
    useState<boolean>(false);
  const [alias, setAlias] = useState<string>('symmetric-encryption');
  const [textToBeEncrypted, setTextToBeEncrypted] = useState<string>(
    'simple text to encrypt'
  );
  const [decryptedText, setDecryptedText] = useState<string>();
  const [encryptedText, setEncryptedText] = useState<string>();
  const [ivText, setIvText] = useState<string>('');

  const setSuccessMessage = useCallback((msg: string) => {
    setError(false);
    setStatus(msg);
  }, []);

  const setErrorMessage = useCallback((msg: string) => {
    setError(true);
    setStatus(msg);
  }, []);

  const createKey = useCallback(async () => {
    setStatus(undefined);
    try {
      await DeviceCrypto.getOrCreateSymmetricEncryptionKey(alias, {
        accessLevel,
        invalidateOnNewBiometry
      });
      setIsKeyExists(await DeviceCrypto.isKeyExists(alias));
      setSuccessMessage('Encryption key created successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, [accessLevel, alias, invalidateOnNewBiometry, setErrorMessage, setSuccessMessage]);

  const encrypt = useCallback(async () => {
    setStatus(undefined);
    setEncryptedText(undefined);
    setDecryptedText(undefined);
    try {
      const base64bytesToEncrypt = base64.encode(utf8.encode(textToBeEncrypted));
      const res = await DeviceCrypto.encryptSymmetrically(alias, base64bytesToEncrypt, {
        biometryTitle: 'Authentication is required',
        biometrySubTitle: 'Encryption',
        biometryDescription: 'Authenticate your self to encrypt given text.'
      });
      setIvText(res.initializationVector);
      setEncryptedText(res.cipherText);
      setSuccessMessage('Data encrypted successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, [alias, setErrorMessage, setSuccessMessage, textToBeEncrypted]);

  const decrypt = useCallback(async () => {
    setStatus(undefined);
    try {
      if (null == encryptedText) {
        setErrorMessage("Please set encrypted text");
        return;
      }
      const res = await DeviceCrypto.decryptSymmetrically(alias, encryptedText, ivText, {
        biometryTitle: 'Authentication is required',
        biometrySubTitle: 'Encryption',
        biometryDescription: 'Authenticate your self to encrypt given text.'
      });
      setDecryptedText(utf8.decode(base64.decode(res)));
      setSuccessMessage('Data decrypted successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, [alias, encryptedText, ivText, setErrorMessage, setSuccessMessage]);

  const deleteKey = useCallback(async () => {
    try {
      setStatus(undefined);
      await DeviceCrypto.deleteKey(alias);
      setIsKeyExists(false);
      setSuccessMessage('Key removed successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, [alias, setErrorMessage, setSuccessMessage]);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const setAccessLevelFromDropdown = useCallback((item: any) => setAccessLevel(item.value), []);

  useEffect(() => {
    DeviceCrypto.isKeyExists(alias).then(setIsKeyExists);
  }, [isKeyExists, alias]);

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
        <Button onPress={createKey} title="Create key" color="#007eb7" testID={testID('createKeyButton')}/>
        <Text style={styles.hint}>
          That will create a new key or return public key of the existing key.
        </Text>

        {isKeyExists && (
          <>
            <View style={styles.separator}/>
            <Text>Text to be encrypted</Text>
            <TextInput
              style={styles.input}
              onChangeText={setTextToBeEncrypted}
              multiline={true}
              numberOfLines={10}
              value={textToBeEncrypted}
              testID={testID('input')}/>
            <Button
              onPress={encrypt}
              title="Encrypt the text"
              color="#007eb7"
              testID={testID('encryptButton')}/>
            <View style={styles.separator}/>
            <Text>Encrypted text to decrypt</Text>
            <TextInput
              style={styles.input}
              multiline
              numberOfLines={10}
              onChangeText={setEncryptedText}
              value={encryptedText}
              testID={testID('cipherText')}/>
            <Text>Initialization Vector</Text>
            <TextInput
              style={styles.input}
              onChangeText={setIvText}
              value={ivText}
              testID={testID('iv')}/>
            <Button
              onPress={decrypt}
              title="Decrypt the text"
              color="#007eb7"
              testID={testID('decryptButton')}/>
            {decryptedText && (
              <>
                <Text>Decrypted message</Text>
                <CopiableText text={decryptedText} testID={testID('decryptedData')}/>
              </>
            )}
            <View style={styles.separator}/>
            <Button
              onPress={deleteKey}
              title="Delete the key"
              color="#007eb7"
              testID={testID('removeKeyButton')}/>
          </>
        )}
      </ScrollView>
    </SafeAreaView>
  );
};

export default SymmetricScreen;
