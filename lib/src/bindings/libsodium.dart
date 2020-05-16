import 'dart:ffi';
import 'dart:io';

final libsodium = Platform.isAndroid
      ? DynamicLibrary.open('libsodium.so')
      : DynamicLibrary.process();

// Extension helper for functions returning size_t
// this is a workaround for size_t not being properly supported in ffi. IntPtr 
// almost works, but is sign extended. 
extension Bindings on DynamicLibrary {
  int Function() lookupSizet(String symbolName) => sizeOf<IntPtr>() == 4
      ? this.lookup<NativeFunction<Uint32 Function()>>(symbolName).asFunction()
      : this.lookup<NativeFunction<Uint64 Function()>>(symbolName).asFunction();
}