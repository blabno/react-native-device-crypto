import * as React from "react";
import {
  type StyleProp,
  Text,
  type TextStyle
} from "react-native";
import {
  type FC,
  useCallback
} from "react";
import Clipboard from "@react-native-clipboard/clipboard";


type CopiableTextProps = {
  style?: StyleProp<TextStyle>;
  text?: string;
  testID?: string;
};
const CopiableText: FC<CopiableTextProps> = ({style, text, testID}) => {
  const copyToClipboard = useCallback(
    () => text && Clipboard.setString(text),
    [text]
  );
  return (
    <Text style={style} onLongPress={copyToClipboard} testID={testID}>
      {text}
    </Text>
  );
};

export default CopiableText;
