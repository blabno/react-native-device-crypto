
#ifdef RCT_NEW_ARCH_ENABLED
#import "RNDeviceCryptoSpec.h"

@interface DeviceCrypto : NSObject <NativeDeviceCryptoSpec>
#else
#import <React/RCTBridgeModule.h>

@interface DeviceCrypto : NSObject <RCTBridgeModule>
#endif

@end
