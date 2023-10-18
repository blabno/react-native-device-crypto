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

const Tab = createBottomTabNavigator();

const App: FC = () => (
    <NavigationContainer>
        <Tab.Navigator
            screenOptions={({route}) => ({
                tabBarIcon: ({focused, color, size}) => {
                    let iconName = 'home';

                    switch (route.name) {
                        case 'Home':
                            iconName = focused ? 'home' : 'home-outline';
                            break;
                        case 'Signing':
                            iconName = focused ? 'lock-closed' : 'lock-closed-outline';
                            break;
                        case 'Symmetric':
                            iconName = focused ? 'key' : 'key-outline';
                            break;
                        case 'Biometry':
                            iconName = focused ? 'finger-print' : 'finger-print-outline';
                            break;
                        case 'Asymmetric':
                            iconName = focused ? 'barbell' : 'barbell-outline';
                            break;
                    }

                    return <Ionicons name={iconName} size={size} color={color}/>;
                },
                tabBarActiveTintColor: 'tomato',
                tabBarInactiveTintColor: 'gray'
            })}>
            <Tab.Screen name="Home" component={HomeScreen}/>
            <Tab.Screen name="Signing" component={SigningScreen}/>
            <Tab.Screen name="Symmetric" component={SymmetricScreen}/>
            <Tab.Screen name="Asymmetric" component={AsymmetricEncryptionScreen}/>
            <Tab.Screen name="Biometry" component={BiometryScreen}/>
        </Tab.Navigator>
    </NavigationContainer>
);

export default App;
