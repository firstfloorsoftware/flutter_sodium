import 'dart:ffi';
import 'core.dart';
import 'package:ffi/ffi.dart';

// ignore_for_file: non_constant_identifier_names

final int Function() crypto_generichash_bytes_min =
    lookup_sizet("crypto_generichash_bytes_min");

final int Function() crypto_generichash_bytes_max =
    lookup_sizet("crypto_generichash_bytes_max");

final int Function() crypto_generichash_bytes =
    lookup_sizet("crypto_generichash_bytes");

final int Function() crypto_generichash_keybytes_min =
    lookup_sizet("crypto_generichash_keybytes_min");

final int Function() crypto_generichash_keybytes_max =
    lookup_sizet("crypto_generichash_keybytes_max");

final int Function() crypto_generichash_keybytes =
    lookup_sizet("crypto_generichash_keybytes");

final Pointer<Utf8> Function() crypto_generichash_primitive = libsodium
    .lookup<NativeFunction<Pointer<Utf8> Function()>>(
        "crypto_generichash_primitive")
    .asFunction();

final int Function(Pointer<Uint8> out, int outlen, Pointer<Uint8> i, int inlen,
        Pointer<Uint8> key, int keylen) crypto_generichash =
    libsodium
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, Int32,
                    Pointer<Uint8>, IntPtr keylen)>>("crypto_generichash")
        .asFunction();

final void Function(Pointer<Uint8> k) crypto_generichash_keygen = libsodium
    .lookup<NativeFunction<Void Function(Pointer<Uint8>)>>(
        "crypto_generichash_keygen")
    .asFunction();
