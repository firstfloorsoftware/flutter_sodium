import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'bindings/core.dart';
import 'bindings/crypto_generichash.dart';
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
  // crypto_generichash
  //
  static int get cryptoGenerichashBytesMin => crypto_generichash_bytes_min();
  static int get cryptoGenerichashBytesMax => crypto_generichash_bytes_max();
  static int get cryptoGenerichashBytes => crypto_generichash_bytes();
  static int get cryptoGenerichashKeybytesMin =>
      crypto_generichash_keybytes_min();
  static int get cryptoGenerichashKeybytesMax =>
      crypto_generichash_keybytes_max();
  static int get cryptoGenerichashKeybytes => crypto_generichash_keybytes();
  static String get cryptoGenerichashPrimitive =>
      Utf8.fromUtf8(crypto_generichash_primitive());

  static Uint8List cryptoGenerichash(int outlen, Uint8List i, Uint8List key) {
    assert(outlen != null);
    assert(i != null);
    RangeError.checkValueInInterval(
        outlen, cryptoGenerichashBytesMin, cryptoGenerichashBytesMax);
    if (key != null) {
      RangeError.checkValueInInterval(key.length, cryptoGenerichashKeybytesMin,
          cryptoGenerichashKeybytesMax, 'key', 'Invalid length');
    }

    final _out = allocate<Uint8>(count: outlen);
    final _in = i.toPointer();
    final _key = key.toPointer();

    try {
      crypto_generichash(_out, outlen, _in, i.length, _key, key?.length ?? 0)
          .requireSuccess();
      return _out.toList(outlen);
    } finally {
      free(_out);
      free(_in);
      if (_key != null) {
        free(_key);
      }
    }
  }

  static Uint8List cryptoGenerichashKeygen() {
    final _k = allocate<Uint8>(count: cryptoGenerichashKeybytes);
    try {
      crypto_generichash_keygen(_k);
      return _k.toList(cryptoGenerichashKeybytes);
    } finally {
      free(_k);
    }
  }

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
  static String get cryptoPwhashPrimitive =>
      Utf8.fromUtf8(crypto_pwhash_primitive());

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

    final _out = allocate<Uint8>(count: outlen);
    final _passwd = passwd.toPointer();
    final _salt = salt.toPointer();
    try {
      crypto_pwhash(_out, outlen, _passwd, passwd.length, _salt, opslimit,
              memlimit, alg)
          .requireSuccess();

      return _out.toList(outlen);
    } finally {
      free(_out);
      free(_passwd);
      free(_salt);
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

    final _out = allocate<Uint8>(count: cryptoPwhashStrbytes);
    final _passwd = passwd.toPointer();
    try {
      crypto_pwhash_str(_out, _passwd, passwd.length, opslimit, memlimit)
          .requireSuccess();
      return _out.toList(cryptoPwhashStrbytes);
    } finally {
      free(_out);
      free(_passwd);
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

    final _out = allocate<Uint8>(count: cryptoPwhashStrbytes);
    final _passwd = passwd.toPointer();
    try {
      crypto_pwhash_str_alg(
              _out, _passwd, passwd.length, opslimit, memlimit, alg)
          .requireSuccess();
      return _out.toList(cryptoPwhashStrbytes);
    } finally {
      free(_out);
      free(_passwd);
    }
  }

  static int cryptoPwhashStrVerify(Uint8List str, Uint8List passwd) {
    assert(str != null);
    assert(passwd != null);
    RangeError.checkValueInInterval(str.length, cryptoPwhashStrbytes,
        cryptoPwhashStrbytes, 'str', 'Invalid length');
    RangeError.checkValueInInterval(passwd.length, cryptoPwhashPasswdMin,
        cryptoPwhashPasswdMax, 'passwd', 'Invalid length');
    final _str = str.toPointer();
    final _passwd = passwd.toPointer();
    try {
      return crypto_pwhash_str_verify(_str, _passwd, passwd.length);
    } finally {
      free(_passwd);
      free(_str);
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

    final _str = str.toPointer();
    try {
      return crypto_pwhash_str_needs_rehash(_str, opslimit, memlimit);
    } finally {
      free(_str);
    }
  }

  //
  // randombytes
  //
  static int get randombytesSeedbytes => randombytes_seedbytes();

  static Uint8List randombytesBuf(int size) {
    assert(size != null);
    RangeError.checkNotNegative(size);

    final _buf = allocate<Uint8>(count: size);
    try {
      randombytes_buf(_buf, size);
      return _buf.toList(size);
    } finally {
      free(_buf);
    }
  }

  static Uint8List randombytesBufDeterministic(int size, Uint8List seed) {
    assert(size != null);
    assert(seed != null);
    RangeError.checkNotNegative(size);
    RangeError.checkValueInInterval(seed.length, randombytesSeedbytes,
        randombytesSeedbytes, 'seed', 'Invalid length');

    final _buf = allocate<Uint8>(count: size);
    final _seed = seed.toPointer();
    try {
      randombytes_buf_deterministic(_buf, size, _seed);
      return _buf.toList(size);
    } finally {
      free(_buf);
      free(_seed);
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
