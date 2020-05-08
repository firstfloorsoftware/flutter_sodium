import 'dart:ffi';
import 'dart:io';

// ignore_for_file: non_constant_identifier_names

final DynamicLibrary libsodium = Platform.isAndroid
    ? DynamicLibrary.open("libsodium.so")
    : DynamicLibrary.process();

final int Function() sodium_init = libsodium
    .lookup<NativeFunction<Int32 Function()>>("sodium_init")
    .asFunction();

// HACK: helper for functions returning size_t
int Function() lookup_sizet<TResult>(String symbolName) => sizeOf<IntPtr>() == 4
    ? libsodium
        .lookup<NativeFunction<Uint32 Function()>>(symbolName)
        .asFunction()
    : libsodium
        .lookup<NativeFunction<Uint64 Function()>>(symbolName)
        .asFunction();