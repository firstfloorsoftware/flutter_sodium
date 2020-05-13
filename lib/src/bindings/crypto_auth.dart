import 'dart:ffi';
import 'core.dart';
import 'package:ffi/ffi.dart';

// ignore_for_file: non_constant_identifier_names

final int Function() crypto_auth_bytes = lookup_sizet("crypto_auth_bytes");

final int Function() crypto_auth_keybytes =
    lookup_sizet("crypto_auth_keybytes");

final Pointer<Utf8> Function() crypto_auth_primitive = libsodium
    .lookup<NativeFunction<Pointer<Utf8> Function()>>("crypto_auth_primitive")
    .asFunction();

final int Function(
        Pointer<Uint8> out, Pointer<Uint8> i, int inlen, Pointer<Uint8> k)
    crypto_auth = libsodium
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Uint64,
                    Pointer<Uint8>)>>("crypto_auth")
        .asFunction();

final int Function(
        Pointer<Uint8> h, Pointer<Uint8> i, int inlen, Pointer<Uint8> k)
    crypto_auth_verify = libsodium
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Uint64,
                    Pointer<Uint8>)>>("crypto_auth_verify")
        .asFunction();

final void Function(Pointer<Uint8> k) crypto_auth_keygen = libsodium
    .lookup<NativeFunction<Void Function(Pointer<Uint8>)>>("crypto_auth_keygen")
    .asFunction();
