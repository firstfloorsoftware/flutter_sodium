import 'dart:ffi';
import 'core.dart';
import 'package:ffi/ffi.dart';

// ignore_for_file: non_constant_identifier_names

final int Function() crypto_kx_publickeybytes =
    lookup_sizet("crypto_kx_publickeybytes");

final int Function() crypto_kx_secretkeybytes =
    lookup_sizet("crypto_kx_secretkeybytes");

final int Function() crypto_kx_seedbytes = lookup_sizet("crypto_kx_seedbytes");

final int Function() crypto_kx_sessionkeybytes =
    lookup_sizet("crypto_kx_sessionkeybytes");

final Pointer<Utf8> Function() crypto_kx_primitive = libsodium
    .lookup<NativeFunction<Pointer<Utf8> Function()>>("crypto_kx_primitive")
    .asFunction();

final int Function(Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed)
    crypto_kx_seed_keypair = libsodium
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>,
                    Pointer<Uint8>)>>("crypto_kx_seed_keypair")
        .asFunction();

final int Function(Pointer<Uint8> pk, Pointer<Uint8> sk) crypto_kx_keypair =
    libsodium
        .lookup<NativeFunction<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>>(
            "crypto_kx_keypair")
        .asFunction();

final int Function(
        Pointer<Uint8> rx,
        Pointer<Uint8> tx,
        Pointer<Uint8> client_pk,
        Pointer<Uint8> client_sk,
        Pointer<Uint8> server_pk) crypto_kx_client_session_keys =
    libsodium
        .lookup<
            NativeFunction<
                Int32 Function(
                    Pointer<Uint8>,
                    Pointer<Uint8>,
                    Pointer<Uint8>,
                    Pointer<Uint8>,
                    Pointer<Uint8>)>>("crypto_kx_client_session_keys")
        .asFunction();

final int Function(
        Pointer<Uint8> rx,
        Pointer<Uint8> tx,
        Pointer<Uint8> server_pk,
        Pointer<Uint8> server_sk,
        Pointer<Uint8> client_pk) crypto_kx_server_session_keys =
    libsodium
        .lookup<
            NativeFunction<
                Int32 Function(
                    Pointer<Uint8>,
                    Pointer<Uint8>,
                    Pointer<Uint8>,
                    Pointer<Uint8>,
                    Pointer<Uint8>)>>("crypto_kx_server_session_keys")
        .asFunction();
