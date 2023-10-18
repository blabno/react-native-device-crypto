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
};
const CopiableText: FC<CopiableTextProps> = ({style, text}) => {
    const copyToClipboard = useCallback(
        () => text && Clipboard.setString(text),
        [text]
    );
    return (
        <Text style={style} onLongPress={copyToClipboard}>
            {text}
        </Text>
    );
};

export default CopiableText;
