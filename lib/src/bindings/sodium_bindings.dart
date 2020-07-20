import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'libsodium.dart';

// ignore_for_file: non_constant_identifier_names

class SodiumBindings {
  final int Function() sodium_init = libsodium
      .lookup<NativeFunction<Int32 Function()>>('sodium_init')
      .asFunction();
  final Pointer<Utf8> Function() sodium_version_string = libsodium
      .lookup<NativeFunction<Pointer<Utf8> Function()>>('sodium_version_string')
      .asFunction();
  final int Function() sodium_library_version_major = libsodium
      .lookup<NativeFunction<Int32 Function()>>('sodium_library_version_major')
      .asFunction();
  final int Function() sodium_library_version_minor = libsodium
      .lookup<NativeFunction<Int32 Function()>>('sodium_library_version_minor')
      .asFunction();
  final int Function() sodium_library_minimal = libsodium
      .lookup<NativeFunction<Int32 Function()>>('sodium_library_minimal')
      .asFunction();

  final Pointer<Utf8> Function(
          Pointer<Uint8> hex, int hex_maxlen, Pointer<Uint8> bin, int bin_len)
      sodium_bin2hex = libsodium
          .lookup<
              NativeFunction<
                  Pointer<Utf8> Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>,
                      IntPtr)>>('sodium_bin2hex')
          .asFunction();

  final int Function(
          Pointer<Uint8> bin,
          int bin_maxlen,
          Pointer<Utf8> hex,
          int hex_len,
          Pointer<Utf8> ignore,
          Pointer<Uint8> bin_len,
          Pointer<Uint8> hex_end) sodium_hex2bin =
      libsodium
          .lookup<
              NativeFunction<
                  Int32 Function(
                      Pointer<Uint8>,
                      IntPtr,
                      Pointer<Utf8>,
                      IntPtr,
                      Pointer<Utf8>,
                      Pointer<Uint8>,
                      Pointer<Uint8>)>>('sodium_hex2bin')
          .asFunction();
}
