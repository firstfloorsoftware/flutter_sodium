import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'bindings/core.dart';
import 'bindings/crypto_pwhash.dart';
import 'bindings/random_bytes.dart';
import 'bindings/version.dart';
import 'extensions.dart';

class Sodium {
  //
  // init
  //
  static void sodiumInit() => sodium_init();

  //
  // crypto_pwhash
  //
  static int get cryptoPwhashAlgArgon2i13 => crypto_pwhash_alg_argon2i13();
  static int get cryptoPwhashAlgArgon2id13 => crypto_pwhash_alg_argon2id13();
  static int get cryptoPwhashAlgDefault => crypto_pwhash_alg_default();
  static int get cryptoPwhashBytesMin => crypto_pwhash_bytes_min();
  static int get cryptoPwhashBytesMax => crypto_pwhash_bytes_max();
  static int get cryptoPwhashPasswdMin => crypto_pwhash_passwd_min();
  static int get cryptoPwhashPasswdMax => crypto_pwhash_passwd_max();
  static int get cryptoPwhashSaltbytes => crypto_pwhash_saltbytes();
  static int get cryptoPwhashStrbytes => crypto_pwhash_strbytes();
  static String get cryptoPwhashStrprefix =>
      Utf8.fromUtf8(crypto_pwhash_strprefix());
  static int get cryptoPwhashOpslimitMin => crypto_pwhash_opslimit_min();
  static int get cryptoPwhashOpslimitMax => crypto_pwhash_opslimit_max();
  static int get cryptoPwhashMemlimitMin => crypto_pwhash_memlimit_min();
  static int get cryptoPwhashMemlimitMax => crypto_pwhash_memlimit_max();
  static int get cryptoPwhashOpslimitInteractive =>
      crypto_pwhash_opslimit_interactive();
  static int get cryptoPwhashMemlimitInteractive =>
      crypto_pwhash_memlimit_interactive();
  static int get cryptoPwhashOpslimitModerate =>
      crypto_pwhash_opslimit_moderate();
  static int get cryptoPwhashMemlimitModerate =>
      crypto_pwhash_memlimit_moderate();
  static int get cryptoPwhashOpslimitSensitive =>
      crypto_pwhash_opslimit_sensitive();
  static int get cryptoPwhashMemlimitSensitive =>
      crypto_pwhash_memlimit_sensitive();

  static Uint8List cryptoPwhash(int outlen, Uint8List passwd, Uint8List salt,
      int opslimit, int memlimit, int alg) {
    assert(outlen != null);
    assert(passwd != null);
    assert(salt != null);
    assert(opslimit != null);
    assert(memlimit != null);
    assert(alg != null);
    RangeError.checkValueInInterval(
        outlen, cryptoPwhashBytesMin, cryptoPwhashBytesMax, 'outlen');
    RangeError.checkValueInInterval(passwd.length, cryptoPwhashPasswdMin,
        cryptoPwhashPasswdMax, 'passwd', 'Invalid length');
    RangeError.checkValueInInterval(salt.length, cryptoPwhashSaltbytes,
        cryptoPwhashSaltbytes, 'salt', 'Invalid length');
    RangeError.checkValueInInterval(
        opslimit, cryptoPwhashOpslimitMin, cryptoPwhashOpslimitMax, 'opslimit');
    RangeError.checkValueInInterval(
        memlimit, cryptoPwhashMemlimitMin, cryptoPwhashMemlimitMax, 'memlimit');
    RangeError.checkValueInInterval(
        alg, cryptoPwhashAlgArgon2i13, cryptoPwhashAlgArgon2id13, 'alg');

    final out = allocate<Uint8>(count: outlen);
    final p = passwd.toPointer();
    final s = salt.toPointer();
    try {
      crypto_pwhash(out, outlen, p, passwd.length, s, opslimit, memlimit, alg)
          .requireSuccess();

      return out.toList(outlen);
    } finally {
      free(out);
      free(p);
      free(s);
    }
  }

  static Uint8List cryptoPwhashStr(
      Uint8List passwd, int opslimit, int memlimit) {
    assert(passwd != null);
    assert(opslimit != null);
    assert(memlimit != null);
    RangeError.checkValueInInterval(passwd.length, cryptoPwhashPasswdMin,
        cryptoPwhashPasswdMax, 'passwd', 'Invalid length');
    RangeError.checkValueInInterval(
        opslimit, cryptoPwhashOpslimitMin, cryptoPwhashOpslimitMax, 'opslimit');
    RangeError.checkValueInInterval(
        memlimit, cryptoPwhashMemlimitMin, cryptoPwhashMemlimitMax, 'memlimit');

    final out = allocate<Uint8>(count: cryptoPwhashStrbytes);
    final p = passwd.toPointer();
    try {
      crypto_pwhash_str(out, p, passwd.length, opslimit, memlimit)
          .requireSuccess();
      return out.toList(cryptoPwhashStrbytes);
    } finally {
      free(out);
      free(p);
    }
  }

  static Uint8List cryptoPwhashStrAlg(
      Uint8List passwd, int opslimit, int memlimit, int alg) {
    assert(passwd != null);
    assert(opslimit != null);
    assert(memlimit != null);
    assert(alg != null);
    RangeError.checkValueInInterval(passwd.length, cryptoPwhashPasswdMin,
        cryptoPwhashPasswdMax, 'passwd', 'Invalid length');
    RangeError.checkValueInInterval(
        opslimit, cryptoPwhashOpslimitMin, cryptoPwhashOpslimitMax, 'opslimit');
    RangeError.checkValueInInterval(
        memlimit, cryptoPwhashMemlimitMin, cryptoPwhashMemlimitMax, 'memlimit');
    RangeError.checkValueInInterval(
        alg, cryptoPwhashAlgArgon2i13, cryptoPwhashAlgArgon2id13, 'alg');

    final out = allocate<Uint8>(count: cryptoPwhashStrbytes);
    final p = passwd.toPointer();
    try {
      crypto_pwhash_str_alg(out, p, passwd.length, opslimit, memlimit, alg)
          .requireSuccess();
      return out.toList(cryptoPwhashStrbytes);
    } finally {
      free(out);
      free(p);
    }
  }

  static int cryptoPwhashStrVerify(Uint8List str, Uint8List passwd) {
    assert(str != null);
    assert(passwd != null);
    RangeError.checkValueInInterval(str.length, cryptoPwhashStrbytes,
        cryptoPwhashStrbytes, 'str', 'Invalid length');
    RangeError.checkValueInInterval(passwd.length, cryptoPwhashPasswdMin,
        cryptoPwhashPasswdMax, 'passwd', 'Invalid length');
    final s = str.toPointer();
    final p = passwd.toPointer();
    try {
      return crypto_pwhash_str_verify(s, p, passwd.length);
    } finally {
      free(p);
      free(s);
    }
  }

  static int cryptoPwhashStrNeedsRehash(
      Uint8List str, int opslimit, int memlimit) {
    assert(str != null);
    assert(opslimit != null);
    assert(memlimit != null);
    RangeError.checkValueInInterval(str.length, cryptoPwhashStrbytes,
        cryptoPwhashStrbytes, 'str', 'Invalid length');
    RangeError.checkValueInInterval(
        opslimit, cryptoPwhashOpslimitMin, cryptoPwhashOpslimitMax, 'opslimit');
    RangeError.checkValueInInterval(
        memlimit, cryptoPwhashMemlimitMin, cryptoPwhashMemlimitMax, 'memlimit');

    final s = str.toPointer();
    try {
      return crypto_pwhash_str_needs_rehash(s, opslimit, memlimit);
    } finally {
      free(s);
    }
  }

  static String get cryptoPwhashPrimitive =>
      Utf8.fromUtf8(crypto_pwhash_primitive());

  //
  // randombytes
  //
  static int get randombytesSeedbytes => randombytes_seedbytes();

  static Uint8List randombytesBuf(int size) {
    assert(size != null);
    RangeError.checkNotNegative(size);

    final buf = allocate<Uint8>(count: size);
    randombytes_buf(buf, size);
    try {
      return buf.toList(size);
    } finally {
      free(buf);
    }
  }

  static Uint8List randombytesBufDeterministic(int size, Uint8List seed) {
    assert(size != null);
    assert(seed != null);
    RangeError.checkNotNegative(size);
    RangeError.checkValueInInterval(seed.length, randombytesSeedbytes,
        randombytesSeedbytes, 'seed', 'Invalid length');

    final buf = allocate<Uint8>(count: size);
    final s = seed.toPointer();
    try {
      randombytes_buf_deterministic(buf, size, s);
      return buf.toList(size);
    } finally {
      free(buf);
      free(s);
    }
  }

  static int randombytesRandom() => randombytes_random();

  static int randombytesUniform(int upperBound) {
    assert(upperBound != null);
    RangeError.checkNotNegative(upperBound);

    return randombytes_uniform(upperBound);
  }

  static void randombytesStir() => randombytes_stir();
  static void randombytesClose() => randombytes_close();

  static String get randombytesImplementationName =>
      Utf8.fromUtf8(randombytes_implementation_name());

  //
  // version
  //
  static String get sodiumVersionString =>
      Utf8.fromUtf8(sodium_version_string());
  static int get sodiumLibraryVersionMajor => sodium_library_version_major();
  static int get sodiumLibraryVersionMinor => sodium_library_version_minor();
  static int get sodiumLibraryMinimal => sodium_library_minimal();
}
