import * as React from 'react';

import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import Ionicons from 'react-native-vector-icons/Ionicons';
import HomeScreen from './HomeScreen';
import AsymmetricEncryptionScreen from './AsymmetricEncryptionScreen';
import SigningScreen from './SigningScreen';
import SymmetricScreen from './SymmetricScreen';
import BiometryScreen from './BiometryScreen';
import type {FC} from "react";
import {testID} from "./util";
import HeaderTitle from "@react-navigation/elements/src/Header/HeaderTitle";
import EncryptionWithPasswordScreen from './EncryptionWithPasswordScreen';

const Tab = createBottomTabNavigator();

const App: FC = () => (
    <NavigationContainer>
        <Tab.Navigator
            screenOptions={({route}) => ({
                headerTitle: props => (<HeaderTitle {...props} testID={testID('title')}/>),
                tabBarIcon: ({focused, color, size}) => {
                    let iconName = 'home';
                    let testId = 'home';

                    switch (route.name) {
                      case 'Home':
                        iconName = focused ? 'home' : 'home-outline';
                        break;
                      case 'Signing':
                        testId = 'signing';
                        iconName = focused ? 'lock-closed' : 'lock-closed-outline';
                        break;
                      case 'Symmetric':
                        testId = 'symmetric';
                        iconName = focused ? 'key' : 'key-outline';
                        break;
                      case 'Biometry':
                        testId = 'biometry';
                        iconName = focused ? 'finger-print' : 'finger-print-outline';
                        break;
                      case 'Asymmetric':
                        testId = 'asymmetric';
                        iconName = focused ? 'barbell' : 'barbell-outline';
                        break;
                      case 'With Password':
                        testId = 'encryptionWithPassword';
                        iconName = focused ? 'keypad' : 'keypad-outline';
                        break;
                    }

                  return <Ionicons name={iconName} size={size} color={color} testID={testID(testId)}/>;
                },
                tabBarActiveTintColor: 'tomato',
                tabBarInactiveTintColor: 'gray',
            })}>
            <Tab.Screen name="Home" component={HomeScreen}/>
            <Tab.Screen name="Signing" component={SigningScreen}/>
            <Tab.Screen name="Symmetric" component={SymmetricScreen}/>
            <Tab.Screen name="Asymmetric" component={AsymmetricEncryptionScreen}/>
            <Tab.Screen name="With Password" component={EncryptionWithPasswordScreen}/>
            <Tab.Screen name="Biometry" component={BiometryScreen}/>
        </Tab.Navigator>
    </NavigationContainer>
);

export default App;
