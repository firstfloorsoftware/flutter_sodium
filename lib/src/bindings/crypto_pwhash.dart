import 'dart:ffi';
import 'core.dart';
import 'package:ffi/ffi.dart';

// ignore_for_file: non_constant_identifier_names

final int Function() crypto_pwhash_alg_argon2i13 = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_alg_argon2i13")
    .asFunction();

final int Function() crypto_pwhash_alg_argon2id13 = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_alg_argon2id13")
    .asFunction();

final int Function() crypto_pwhash_alg_default = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_alg_default")
    .asFunction();

final int Function() crypto_pwhash_bytes_min = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_bytes_min")
    .asFunction();

final int Function() crypto_pwhash_bytes_max = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_bytes_max")
    .asFunction();

final int Function() crypto_pwhash_passwd_min = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_passwd_min")
    .asFunction();

final int Function() crypto_pwhash_passwd_max = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_passwd_max")
    .asFunction();

final int Function() crypto_pwhash_saltbytes = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_saltbytes")
    .asFunction();

final int Function() crypto_pwhash_strbytes = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_strbytes")
    .asFunction();

final Pointer<Utf8> Function() crypto_pwhash_strprefix = libsodium
    .lookup<NativeFunction<Pointer<Utf8> Function()>>("crypto_pwhash_strprefix")
    .asFunction();

final int Function() crypto_pwhash_opslimit_min = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_opslimit_min")
    .asFunction();

final int Function() crypto_pwhash_opslimit_max = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_opslimit_max")
    .asFunction();

final int Function() crypto_pwhash_memlimit_min = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_memlimit_min")
    .asFunction();

final int Function() crypto_pwhash_memlimit_max = libsodium
    .lookup<NativeFunction<Uint32 Function()>>("crypto_pwhash_memlimit_max")
    .asFunction();

final int Function() crypto_pwhash_opslimit_interactive = libsodium
    .lookup<NativeFunction<Uint32 Function()>>(
        "crypto_pwhash_opslimit_interactive")
    .asFunction();

final int Function() crypto_pwhash_memlimit_interactive = libsodium
    .lookup<NativeFunction<Uint32 Function()>>(
        "crypto_pwhash_memlimit_interactive")
    .asFunction();

final int Function() crypto_pwhash_opslimit_moderate = libsodium
    .lookup<NativeFunction<Uint32 Function()>>(
        "crypto_pwhash_opslimit_moderate")
    .asFunction();

final int Function() crypto_pwhash_memlimit_moderate = libsodium
    .lookup<NativeFunction<Uint32 Function()>>(
        "crypto_pwhash_memlimit_moderate")
    .asFunction();

final int Function() crypto_pwhash_opslimit_sensitive = libsodium
    .lookup<NativeFunction<Uint32 Function()>>(
        "crypto_pwhash_opslimit_sensitive")
    .asFunction();

final int Function() crypto_pwhash_memlimit_sensitive = libsodium
    .lookup<NativeFunction<Uint32 Function()>>(
        "crypto_pwhash_memlimit_sensitive")
    .asFunction();

final int Function(Pointer<Uint8> out, int, Pointer<Uint8> passwd,
        int passwdlen, Pointer<Uint8> salt, int opslimit, int memlimit, int alg)
    crypto_pwhash = libsodium
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Uint64, Pointer<Uint8>, Uint64,
                    Pointer<Uint8>, Uint64, Uint32, Int32)>>("crypto_pwhash")
        .asFunction();

final int Function(Pointer<Uint8> out, Pointer<Uint8> passwd, int passwdlen,
        int opslimit, int memlimit) crypto_pwhash_str =
    libsodium
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Uint64, Uint64,
                    Uint32)>>("crypto_pwhash_str")
        .asFunction();

final int Function(Pointer<Uint8> out, Pointer<Uint8> passwd, int passwdlen,
        int opslimit, int memlimit, int alg) crypto_pwhash_str_alg =
    libsodium
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Uint64, Uint64,
                    Uint32, Int32)>>("crypto_pwhash_str_alg")
        .asFunction();

final int Function(Pointer<Uint8> str, Pointer<Uint8> passwd, int passwdlen)
    crypto_pwhash_str_verify = libsodium
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>,
                    Uint64)>>("crypto_pwhash_str_verify")
        .asFunction();

final int Function(Pointer<Uint8> str, int opslimit, int memlimit)
    crypto_pwhash_str_needs_rehash = libsodium
        .lookup<NativeFunction<Int32 Function(Pointer<Uint8>, Uint64, Uint32)>>(
            "crypto_pwhash_str_needs_rehash")
        .asFunction();

final Pointer<Utf8> Function() crypto_pwhash_primitive = libsodium
    .lookup<NativeFunction<Pointer<Utf8> Function()>>("crypto_pwhash_primitive")
    .asFunction();
