import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'bindings/core.dart';
import 'bindings/crypto_box.dart';
import 'bindings/crypto_generichash.dart';
import 'bindings/crypto_pwhash.dart';
import 'bindings/crypto_sign.dart';
import 'bindings/random_bytes.dart';
import 'bindings/version.dart';
import 'extensions.dart';
import 'names.dart';

class Sodium {
  //
  // init
  //
  static void sodiumInit() => sodium_init();

  //
  // crypto_box
  //
  static int get cryptoBoxSeedbytes => crypto_box_seedbytes();
  static int get cryptoBoxPublickeybytes => crypto_box_publickeybytes();
  static int get cryptoBoxSecretkeybytes => crypto_box_secretkeybytes();
  static int get cryptoBoxNoncebytes => crypto_box_noncebytes();
  static int get cryptoBoxMacbytes => crypto_box_macbytes();
  static int get cryptoBoxMessagebytesMax => crypto_box_messagebytes_max();
  static int get cryptoBoxSealbytes => crypto_box_sealbytes();
  static int get cryptoBoxBeforenmbytes => crypto_box_beforenmbytes();
  static String get cryptoBoxPrimitive => Utf8.fromUtf8(crypto_box_primitive());

  static Map<String, Uint8List> cryptoBoxSeedKeypair(Uint8List seed) {
    assert(seed != null);
    RangeError.checkValueInInterval(seed.length, cryptoBoxSeedbytes,
        cryptoBoxSeedbytes, 'seed', 'Invalid length');
    final _pk = allocate<Uint8>(count: cryptoBoxPublickeybytes);
    final _sk = allocate<Uint8>(count: cryptoBoxSecretkeybytes);
    final _seed = seed.toPointer();

    try {
      crypto_box_seed_keypair(_pk, _sk, _seed).requireSuccess();
      return {
        Names.pk: _pk.toList(cryptoBoxPublickeybytes),
        Names.sk: _sk.toList(cryptoBoxSecretkeybytes)
      };
    } finally {
      free(_pk);
      free(_sk);
      free(_seed);
    }
  }

  static Map<String, Uint8List> cryptoBoxKeypair() {
    final _pk = allocate<Uint8>(count: cryptoBoxPublickeybytes);
    final _sk = allocate<Uint8>(count: cryptoBoxSecretkeybytes);

    try {
      crypto_box_keypair(_pk, _sk).requireSuccess();
      return {
        Names.pk: _pk.toList(cryptoBoxPublickeybytes),
        Names.sk: _sk.toList(cryptoBoxSecretkeybytes)
      };
    } finally {
      free(_pk);
      free(_sk);
    }
  }

  static Uint8List cryptoBoxEasy(
      Uint8List m, Uint8List n, Uint8List pk, Uint8List sk) {
    assert(m != null);
    assert(n != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final _c = allocate<Uint8>(count: m.length + cryptoBoxMacbytes);
    final _m = m.toPointer();
    final _n = n.toPointer();
    final _pk = pk.toPointer();
    final _sk = sk.toPointer();

    try {
      crypto_box_easy(_c, _m, m.length, _n, _pk, _sk).requireSuccess();

      return _c.toList(m.length + cryptoBoxMacbytes);
    } finally {
      free(_c);
      free(_m);
      free(_n);
      free(_pk);
      free(_sk);
    }
  }

  static Uint8List cryptoBoxOpenEasy(
      Uint8List c, Uint8List n, Uint8List pk, Uint8List sk) {
    assert(c != null);
    assert(n != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final _m = allocate<Uint8>(count: c.length - cryptoBoxMacbytes);
    final _c = c.toPointer();
    final _n = n.toPointer();
    final _pk = pk.toPointer();
    final _sk = sk.toPointer();

    try {
      crypto_box_open_easy(_m, _c, c.length, _n, _pk, _sk).requireSuccess();

      return _m.toList(c.length - cryptoBoxMacbytes);
    } finally {
      free(_m);
      free(_c);
      free(_n);
      free(_pk);
      free(_sk);
    }
  }

  static Map<String, Uint8List> cryptoBoxDetached(
      Uint8List m, Uint8List n, Uint8List pk, Uint8List sk) {
    assert(m != null);
    assert(n != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final _c = allocate<Uint8>(count: m.length);
    final _mac = allocate<Uint8>(count: cryptoBoxMacbytes);
    final _m = m.toPointer();
    final _n = n.toPointer();
    final _pk = pk.toPointer();
    final _sk = sk.toPointer();

    try {
      crypto_box_detached(_c, _mac, _m, m.length, _n, _pk, _sk)
          .requireSuccess();

      return {
        Names.c: _c.toList(m.length),
        Names.mac: _mac.toList(cryptoBoxMacbytes)
      };
    } finally {
      free(_c);
      free(_mac);
      free(_m);
      free(_n);
      free(_pk);
      free(_sk);
    }
  }

  static Uint8List cryptoBoxOpenDetached(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List pk, Uint8List sk) {
    assert(c != null);
    assert(mac != null);
    assert(n != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(mac.length, cryptoBoxMacbytes,
        cryptoBoxMacbytes, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final _m = allocate<Uint8>(count: c.length);
    final _mac = mac.toPointer();
    final _c = c.toPointer();
    final _n = n.toPointer();
    final _pk = pk.toPointer();
    final _sk = sk.toPointer();

    try {
      crypto_box_open_detached(_m, _c, _mac, c.length, _n, _pk, _sk)
          .requireSuccess();

      return _m.toList(c.length);
    } finally {
      free(_m);
      free(_mac);
      free(_c);
      free(_n);
      free(_pk);
      free(_sk);
    }
  }

  static Uint8List cryptoBoxBeforenm(Uint8List pk, Uint8List sk) {
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final _k = allocate<Uint8>(count: cryptoBoxBeforenmbytes);
    final _pk = pk.toPointer();
    final _sk = sk.toPointer();
    try {
      crypto_box_beforenm(_k, _pk, _sk).requireSuccess();

      return _k.toList(cryptoBoxBeforenmbytes);
    } finally {
      free(_k);
      free(_pk);
      free(_sk);
    }
  }

  static Uint8List cryptoBoxEasyAfternm(Uint8List m, Uint8List n, Uint8List k) {
    assert(m != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoBoxBeforenmbytes,
        cryptoBoxBeforenmbytes, 'k', 'Invalid length');

    final _c = allocate<Uint8>(count: m.length + cryptoBoxMacbytes);
    final _m = m.toPointer();
    final _n = n.toPointer();
    final _k = k.toPointer();

    try {
      crypto_box_easy_afternm(_c, _m, m.length, _n, _k).requireSuccess();

      return _c.toList(m.length + cryptoBoxMacbytes);
    } finally {
      free(_c);
      free(_m);
      free(_n);
      free(_k);
    }
  }

  static Uint8List cryptoBoxOpenEasyAfternm(
      Uint8List c, Uint8List n, Uint8List k) {
    assert(c != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoBoxBeforenmbytes,
        cryptoBoxBeforenmbytes, 'k', 'Invalid length');

    final _m = allocate<Uint8>(count: c.length - cryptoBoxMacbytes);
    final _c = c.toPointer();
    final _n = n.toPointer();
    final _k = k.toPointer();

    try {
      crypto_box_open_easy_afternm(_m, _c, c.length, _n, _k).requireSuccess();

      return _m.toList(c.length - cryptoBoxMacbytes);
    } finally {
      free(_m);
      free(_c);
      free(_n);
      free(_k);
    }
  }

  static Map<String, Uint8List> cryptoBoxDetachedAfternm(
      Uint8List m, Uint8List n, Uint8List k) {
    assert(m != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoBoxBeforenmbytes,
        cryptoBoxBeforenmbytes, 'k', 'Invalid length');

    final _c = allocate<Uint8>(count: m.length);
    final _mac = allocate<Uint8>(count: cryptoBoxMacbytes);
    final _m = m.toPointer();
    final _n = n.toPointer();
    final _k = k.toPointer();

    try {
      crypto_box_detached_afternm(_c, _mac, _m, m.length, _n, _k)
          .requireSuccess();

      return {
        Names.c: _c.toList(m.length),
        Names.mac: _mac.toList(cryptoBoxMacbytes)
      };
    } finally {
      free(_c);
      free(_mac);
      free(_m);
      free(_n);
      free(_k);
    }
  }

  static Uint8List cryptoBoxOpenDetachedAfternm(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List k) {
    assert(c != null);
    assert(mac != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(mac.length, cryptoBoxMacbytes,
        cryptoBoxMacbytes, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoBoxBeforenmbytes,
        cryptoBoxBeforenmbytes, 'k', 'Invalid length');

    final _m = allocate<Uint8>(count: c.length);
    final _mac = mac.toPointer();
    final _c = c.toPointer();
    final _n = n.toPointer();
    final _k = k.toPointer();

    try {
      crypto_box_open_detached_afternm(_m, _c, _mac, c.length, _n, _k)
          .requireSuccess();

      return _m.toList(c.length);
    } finally {
      free(_m);
      free(_mac);
      free(_c);
      free(_n);
      free(_k);
    }
  }

  static Uint8List cryptoBoxSeal(Uint8List m, Uint8List pk) {
    assert(m != null);
    assert(pk != null);
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');

    final _c = allocate<Uint8>(count: m.length + cryptoBoxSealbytes);
    final _m = m.toPointer();
    final _pk = pk.toPointer();

    try {
      crypto_box_seal(_c, _m, m.length, _pk).requireSuccess();

      return _c.toList(m.length + cryptoBoxSealbytes);
    } finally {
      free(_c);
      free(_m);
      free(_pk);
    }
  }

  static Uint8List cryptoBoxSealOpen(Uint8List c, Uint8List pk, Uint8List sk) {
    assert(c != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final _m = allocate<Uint8>(count: c.length - cryptoBoxSealbytes);
    final _c = c.toPointer();
    final _pk = pk.toPointer();
    final _sk = sk.toPointer();

    try {
      crypto_box_seal_open(_m, _c, c.length, _pk, _sk).requireSuccess();

      return _m.toList(c.length - cryptoBoxSealbytes);
    } finally {
      free(_m);
      free(_c);
      free(_pk);
      free(_sk);
    }
  }

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
  static int get cryptoGenerichashStatebytes => crypto_generichash_statebytes();

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

  static Pointer<Uint8> cryptoGenerichashInit(Uint8List key, int outlen) {
    assert(outlen != null);
    if (key != null) {
      RangeError.checkValueInInterval(key.length, cryptoGenerichashKeybytesMin,
          cryptoGenerichashKeybytesMax, 'key', 'Invalid length');
    }
    RangeError.checkValueInInterval(
        outlen, cryptoGenerichashBytesMin, cryptoGenerichashBytesMax);

    final _state = allocate<Uint8>(count: cryptoGenerichashStatebytes);
    final _key = key.toPointer();

    try {
      crypto_generichash_init(_state, _key, key?.length ?? 0, outlen)
          .requireSuccess();
      return _state;
    } finally {
      if (_key != null) {
        free(_key);
      }
    }
  }

  static void cryptoGenerichashUpdate(Pointer<Uint8> state, Uint8List i) {
    assert(state != null);
    assert(i != null);

    final _in = i.toPointer();

    try {
      crypto_generichash_update(state, _in, i.length).requireSuccess();
    } finally {
      free(_in);
    }
  }

  static Uint8List cryptoGenerichashFinal(Pointer<Uint8> state, int outlen) {
    assert(state != null);
    assert(outlen != null);
    RangeError.checkValueInInterval(
        outlen, cryptoGenerichashBytesMin, cryptoGenerichashBytesMax);

    final _out = allocate<Uint8>(count: outlen);

    try {
      crypto_generichash_final(state, _out, outlen).requireSuccess();
      return _out.toList(outlen);
    } finally {
      // note: caller is responsible for freeing state
      free(_out);
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
  // crypto_sign
  //
  static int get cryptoSignStatebytes => crypto_sign_statebytes();
  static int get cryptoSignBytes => crypto_sign_bytes();
  static int get cryptoSignSeedbytes => crypto_sign_seedbytes();
  static int get cryptoSignPublickeybytes => crypto_sign_publickeybytes();
  static int get cryptoSignSecretkeybytes => crypto_sign_secretkeybytes();
  static int get cryptoSignMessagebytesMax => crypto_sign_messagebytes_max();
  static String get cryptoSignPrimitive =>
      Utf8.fromUtf8(crypto_sign_primitive());

  static Map<String, Uint8List> cryptoSignSeedKeypair(Uint8List seed) {
    assert(seed != null);
    RangeError.checkValueInInterval(seed.length, cryptoSignSeedbytes,
        cryptoSignSeedbytes, 'seed', 'Invalid length');
    final _pk = allocate<Uint8>(count: cryptoSignPublickeybytes);
    final _sk = allocate<Uint8>(count: cryptoSignSecretkeybytes);
    final _seed = seed.toPointer();

    try {
      crypto_sign_seed_keypair(_pk, _sk, _seed).requireSuccess();
      return {
        Names.pk: _pk.toList(cryptoSignPublickeybytes),
        Names.sk: _sk.toList(cryptoSignSecretkeybytes)
      };
    } finally {
      free(_pk);
      free(_sk);
      free(_seed);
    }
  }

  static Map<String, Uint8List> cryptoSignKeypair() {
    final _pk = allocate<Uint8>(count: cryptoSignPublickeybytes);
    final _sk = allocate<Uint8>(count: cryptoSignSecretkeybytes);

    try {
      crypto_sign_keypair(_pk, _sk).requireSuccess();
      return {
        Names.pk: _pk.toList(cryptoSignPublickeybytes),
        Names.sk: _sk.toList(cryptoSignSecretkeybytes)
      };
    } finally {
      free(_pk);
      free(_sk);
    }
  }

  static Uint8List cryptoSign(Uint8List m, Uint8List sk) {
    assert(m != null);
    assert(sk != null);
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final _sm = allocate<Uint8>(count: m.length + cryptoSignBytes);
    final _smlenP = allocate<Uint64>(count: 1);
    final _m = m.toPointer();
    final _sk = sk.toPointer();

    try {
      crypto_sign(_sm, _smlenP, _m, m.length, _sk).requireSuccess();
      return _sm.toList(_smlenP[0]);
    } finally {
      free(_sm);
      free(_smlenP);
      free(_m);
      free(_sk);
    }
  }

  static Uint8List cryptoSignOpen(Uint8List sm, Uint8List pk) {
    assert(sm != null);
    assert(pk != null);
    RangeError.checkValueInInterval(pk.length, cryptoSignPublickeybytes,
        cryptoSignPublickeybytes, 'pk', 'Invalid length');

    final _m = allocate<Uint8>(count: sm.length - cryptoSignBytes);
    final _mlenP = allocate<Uint64>(count: 1);
    final _sm = sm.toPointer();
    final _pk = pk.toPointer();

    try {
      crypto_sign_open(_m, _mlenP, _sm, sm.length, _pk).requireSuccess();
      return _m.toList(_mlenP[0]);
    } finally {
      free(_m);
      free(_mlenP);
      free(_sm);
      free(_pk);
    }
  }

  static Uint8List cryptoSignDetached(Uint8List m, Uint8List sk) {
    assert(m != null);
    assert(sk != null);
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final _sig = allocate<Uint8>(count: cryptoSignBytes);
    final _siglenP = allocate<Uint64>(count: 1);
    final _m = m.toPointer();
    final _sk = sk.toPointer();

    try {
      crypto_sign_detached(_sig, _siglenP, _m, m.length, _sk).requireSuccess();
      return _sig.toList(_siglenP[0]);
    } finally {
      free(_sig);
      free(_siglenP);
      free(_m);
      free(_sk);
    }
  }

  static int cryptoSignVerifyDetached(
      Uint8List sig, Uint8List m, Uint8List pk) {
    assert(sig != null);
    assert(m != null);
    assert(pk != null);
    RangeError.checkValueInInterval(
        sig.length, cryptoSignBytes, cryptoSignBytes, 'sig', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoSignPublickeybytes,
        cryptoSignPublickeybytes, 'pk', 'Invalid length');

    final _sig = sig.toPointer();
    final _m = m.toPointer();
    final _pk = pk.toPointer();

    try {
      return crypto_sign_verify_detached(_sig, _m, m.length, _pk);
    } finally {
      free(_sig);
      free(_m);
      free(_pk);
    }
  }

  static Pointer<Uint8> cryptoSignInit() {
    final _state = allocate<Uint8>(count: cryptoSignStatebytes);
    crypto_sign_init(_state).requireSuccess();
    return _state;
  }

  static void cryptoSignUpdate(Pointer<Uint8> state, Uint8List m) {
    assert(state != null);
    assert(m != null);

    final _m = m.toPointer();
    try {
      crypto_sign_update(state, _m, m.length).requireSuccess();
    } finally {
      free(_m);
    }
  }

  static Uint8List cryptoSignFinalCreate(Pointer<Uint8> state, Uint8List sk) {
    assert(state != null);
    assert(sk != null);
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final _sig = allocate<Uint8>(count: cryptoSignBytes);
    final _siglenP = allocate<Uint64>(count: 1);
    final _sk = sk.toPointer();
    try {
      crypto_sign_final_create(state, _sig, _siglenP, _sk).requireSuccess();
      return _sig.toList(_siglenP[0]);
    } finally {
      // note: caller is responsible for freeing state
      free(_sig);
      free(_siglenP);
      free(_sk);
    }
  }

  static int cryptoSignFinalVerify(
      Pointer<Uint8> state, Uint8List sig, Uint8List pk) {
    assert(state != null);
    assert(sig != null);
    assert(pk != null);
    RangeError.checkValueInInterval(
        sig.length, cryptoSignBytes, cryptoSignBytes, 'sig', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoSignPublickeybytes,
        cryptoSignPublickeybytes, 'pk', 'Invalid length');

    final _sig = sig.toPointer();
    final _pk = pk.toPointer();
    try {
      return crypto_sign_final_verify(state, _sig, _pk);
    } finally {
      // note: caller is responsible for freeing state
      free(_sig);
      free(_pk);
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
