#import "FlutterSodiumPlugin.h"
#import <flutter_sodium/flutter_sodium-Swift.h>

@implementation FlutterSodiumPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftFlutterSodiumPlugin registerWithRegistrar:registrar];
}
@end
