import 'dart:ffi';
import 'core.dart';
import 'package:ffi/ffi.dart';

// ignore_for_file: non_constant_identifier_names

final int Function() crypto_kdf_bytes_min =
    lookup_sizet("crypto_kdf_bytes_min");

final int Function() crypto_kdf_bytes_max =
    lookup_sizet("crypto_kdf_bytes_max");

final int Function() crypto_kdf_contextbytes =
    lookup_sizet("crypto_kdf_contextbytes");

final int Function() crypto_kdf_keybytes = lookup_sizet("crypto_kdf_keybytes");

final Pointer<Utf8> Function() crypto_kdf_primitive = libsodium
    .lookup<NativeFunction<Pointer<Utf8> Function()>>("crypto_kdf_primitive")
    .asFunction();

final int Function(Pointer<Uint8> subkey, int subkey_len, int subkey_id,
        Pointer<Uint8> ctx, Pointer<Uint8> key) crypto_kdf_derive_from_key =
    libsodium
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, IntPtr, Uint64, Pointer<Uint8>,
                    Pointer<Uint8>)>>("crypto_kdf_derive_from_key")
        .asFunction();

final void Function(Pointer<Uint8> k) crypto_kdf_keygen = libsodium
    .lookup<NativeFunction<Void Function(Pointer<Uint8>)>>("crypto_kdf_keygen")
    .asFunction();
