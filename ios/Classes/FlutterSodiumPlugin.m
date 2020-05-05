#import "FlutterSodiumPlugin.h"
#if __has_include(<flutter_sodium/flutter_sodium-Swift.h>)
#import <flutter_sodium/flutter_sodium-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "flutter_sodium-Swift.h"
#endif

@implementation FlutterSodiumPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftFlutterSodiumPlugin registerWithRegistrar:registrar];
}
@end
