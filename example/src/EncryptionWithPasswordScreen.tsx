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
import DeviceCrypto from 'react-native-device-crypto';
import styles from './styles';
import {type FC, useCallback, useState} from "react";
import {testID} from "./util";
import CopiableText from "./components/CopiableText";

const EncryptionWithPasswordScreen: FC = () => {
  const [error, setError] = useState(false);
  const [iterations, setIterations] = useState('');
  const [status, setStatus] = useState<string>();
  const [password, setPassword] = useState<string>('');
  const [salt, setSalt] = useState<string>('');
  const [textToBeEncrypted, setTextToBeEncrypted] = useState<string>('text to encrypt');
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

  const encrypt = useCallback(async () => {
    setStatus(undefined);
    setEncryptedText(undefined);
    setDecryptedText(undefined);
    const iterationsAsNumber = parseInt(iterations, 10);
    if (isNaN(iterationsAsNumber)) {
      setErrorMessage('Iterations must be a number');
      return;
    }
    try {
      const base64bytesToEncrypt = base64.encode(utf8.encode(textToBeEncrypted));
      const base64Password = base64.encode(utf8.encode(password));
      const base64salt = base64.encode(utf8.encode(salt));
      const res = await DeviceCrypto.encryptSymmetricallyWithPassword(base64Password, base64salt, iterationsAsNumber, base64bytesToEncrypt);
      setIvText(res.initializationVector);
      setEncryptedText(res.cipherText);
      setSuccessMessage('Data encrypted successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, [iterations, password, salt, setErrorMessage, setSuccessMessage, textToBeEncrypted]);

  const decrypt = useCallback(async () => {
    setStatus(undefined);
    setDecryptedText(undefined);
    try {
      if (null == encryptedText) {
        setErrorMessage("Please set encrypted text");
        return;
      }
      const iterationsAsNumber = parseInt(iterations, 10);
      if (isNaN(iterationsAsNumber)) {
        setErrorMessage('Iterations must be a number');
        return;
      }
      const base64Password = base64.encode(utf8.encode(password));
      const base64salt = base64.encode(utf8.encode(salt));
      const res = await DeviceCrypto.decryptSymmetricallyWithPassword(base64Password, base64salt, ivText, iterationsAsNumber, encryptedText);
      setDecryptedText(utf8.decode(base64.decode(res)));
      setSuccessMessage('Data decrypted successfully');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      setErrorMessage(err.message);
    }
  }, [encryptedText, iterations, ivText, password, salt, setErrorMessage, setSuccessMessage]);

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView>
        {status && (<Text testID={testID('status')} style={error ? styles.errorBox : styles.infoBox}>{status}</Text>)}

        <Text>Password</Text>
        <TextInput style={styles.input} onChangeText={setPassword} value={password} testID={testID('password')}/>

        <Text>Salt</Text>
        <TextInput style={styles.input} onChangeText={setSalt} value={salt} testID={testID('salt')}/>

        <Text>Iterations</Text>
        <TextInput style={styles.input} inputMode="numeric" onChangeText={setIterations} value={iterations} testID={testID('iterations')}/>

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
      </ScrollView>
    </SafeAreaView>
  );
};

export default EncryptionWithPasswordScreen;
