import 'dart:ffi';
import 'core.dart';
import 'package:ffi/ffi.dart';

// ignore_for_file: non_constant_identifier_names

final Pointer<Utf8> Function() sodium_version_string = libsodium
    .lookup<NativeFunction<Pointer<Utf8> Function()>>("sodium_version_string")
    .asFunction();

final int Function() sodium_library_version_major = libsodium
    .lookup<NativeFunction<Int32 Function()>>("sodium_library_version_major")
    .asFunction();

final int Function() sodium_library_version_minor = libsodium
    .lookup<NativeFunction<Int32 Function()>>("sodium_library_version_minor")
    .asFunction();

final int Function() sodium_library_minimal = libsodium
    .lookup<NativeFunction<Int32 Function()>>("sodium_library_minimal")
    .asFunction();
