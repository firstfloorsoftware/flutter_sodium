import 'dart:ffi';
import 'dart:io';

// ignore_for_file: non_constant_identifier_names

final DynamicLibrary libsodium = Platform.isAndroid
    ? DynamicLibrary.open("libsodium.so")
    : DynamicLibrary.process();

final int Function() sodium_init = libsodium
    .lookup<NativeFunction<Int32 Function()>>("sodium_init")
    .asFunction();

