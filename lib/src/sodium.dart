import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'bindings/crypto_aead_bindings.dart';
import 'bindings/crypto_auth_bindings.dart';
import 'bindings/crypto_box_bindings.dart';
import 'bindings/crypto_generichash_bindings.dart';
import 'bindings/crypto_kdf_bindings.dart';
import 'bindings/crypto_kx_bindings.dart';
import 'bindings/crypto_onetimeauth_bindings.dart';
import 'bindings/crypto_pwhash_bindings.dart';
import 'bindings/crypto_scalarmult_bindings.dart';
import 'bindings/crypto_secretbox_bindings.dart';
import 'bindings/crypto_shorthash_bindings.dart';
import 'bindings/crypto_sign_bindings.dart';
import 'bindings/randombytes_bindings.dart';
import 'bindings/sodium_bindings.dart';
import 'extensions.dart';
import 'names.dart';

class Sodium {
  static final _chacha20poly1305 = _CryptoAead.chacha20poly1305();
  static final _chacha20poly1305Ietf = _CryptoAead.chacha20poly1305Ietf();
  static final _xchacha20poly1305Ietf = _CryptoAead.xchacha20poly1305Ietf();
  static final _cryptoAuth = CryptoAuthBindings();
  static final _cryptoBox = CryptoBoxBindings();
  static final _cryptoGenerichash = CryptoGenerichashBindings();
  static final _cryptoKdf = CryptoKdfBindings();
  static final _cryptoKx = CryptoKxBindings();
  static final _cryptoOnetimeauth = CryptoOnetimeauthBindings();
  static final _cryptoPwhash = CryptoPwhashBindings();
  static final _cryptoScalarmult = CryptoScalarmultBindings();
  static final _cryptoSecretbox = CryptoSecretboxBindings();
  static final _cryptoShorthash = CryptoShorthashBindings();
  static final _cryptoSign = CryptoSignBindings();
  static final _randombytes = RandombytesBindings();
  static final _sodium = SodiumBindings();

  //
  // crypto_aead_chacha20poly1305
  //
  static int get cryptoAeadChacha20poly1305Keybytes =>
      _chacha20poly1305.keybytes;
  static int get cryptoAeadChacha20poly1305Nsecbytes =>
      _chacha20poly1305.nsecbytes;
  static int get cryptoAeadChacha20poly1305Npubbytes =>
      _chacha20poly1305.npubbytes;
  static int get cryptoAeadChacha20poly1305Abytes => _chacha20poly1305.abytes;
  static int get cryptoAeadChacha20poly1305MessagebytesMax =>
      _chacha20poly1305.messagebytesMax;

  static final cryptoAeadChacha20poly1305Encrypt = _chacha20poly1305.encrypt;
  static final cryptoAeadChacha20poly1305Decrypt = _chacha20poly1305.decrypt;
  static final cryptoAeadChacha20poly1305EncryptDetached =
      _chacha20poly1305.encryptDetached;
  static final cryptoAeadChacha20poly1305DecryptDetached =
      _chacha20poly1305.decryptDetached;
  static final cryptoAeadChacha20poly1305Keygen = _chacha20poly1305.keygen;

  //
  // crypto_aead_chacha20poly1305_ietf
  //
  static int get cryptoAeadChacha20poly1305IetfKeybytes =>
      _chacha20poly1305Ietf.keybytes;
  static int get cryptoAeadChacha20poly1305IetfNsecbytes =>
      _chacha20poly1305Ietf.nsecbytes;
  static int get cryptoAeadChacha20poly1305IetfNpubbytes =>
      _chacha20poly1305Ietf.npubbytes;
  static int get cryptoAeadChacha20poly1305IetfAbytes =>
      _chacha20poly1305Ietf.abytes;
  static int get cryptoAeadChacha20poly1305IetfMessagebytesMax =>
      _chacha20poly1305Ietf.messagebytesMax;

  static final cryptoAeadChacha20poly1305IetfEncrypt =
      _chacha20poly1305Ietf.encrypt;
  static final cryptoAeadChacha20poly1305IetfDecrypt =
      _chacha20poly1305Ietf.decrypt;
  static final cryptoAeadChacha20poly1305IetfEncryptDetached =
      _chacha20poly1305Ietf.encryptDetached;
  static final cryptoAeadChacha20poly1305IetfDecryptDetached =
      _chacha20poly1305Ietf.decryptDetached;
  static final cryptoAeadChacha20poly1305IetfKeygen =
      _chacha20poly1305Ietf.keygen;

  //
  // crypto_aead_xchacha20poly1305_ietf
  //
  static int get cryptoAeadXchacha20poly1305IetfKeybytes =>
      _xchacha20poly1305Ietf.keybytes;
  static int get cryptoAeadXchacha20poly1305IetfNsecbytes =>
      _xchacha20poly1305Ietf.nsecbytes;
  static int get cryptoAeadXchacha20poly1305IetfNpubbytes =>
      _xchacha20poly1305Ietf.npubbytes;
  static int get cryptoAeadXchacha20poly1305IetfAbytes =>
      _xchacha20poly1305Ietf.abytes;
  static int get cryptoAeadXchacha20poly1305IetfMessagebytesMax =>
      _xchacha20poly1305Ietf.messagebytesMax;

  static final cryptoAeadXchacha20poly1305IetfEncrypt =
      _xchacha20poly1305Ietf.encrypt;
  static final cryptoAeadXchacha20poly1305IetfDecrypt =
      _xchacha20poly1305Ietf.decrypt;
  static final cryptoAeadXchacha20poly1305IetfEncryptDetached =
      _xchacha20poly1305Ietf.encryptDetached;
  static final cryptoAeadXchacha20poly1305IetfDecryptDetached =
      _xchacha20poly1305Ietf.decryptDetached;
  static final cryptoAeadXchacha20poly1305IetfKeygen =
      _xchacha20poly1305Ietf.keygen;

  //
  // crypto_auth
  //
  static int get cryptoAuthBytes => _cryptoAuth.crypto_auth_bytes();
  static int get cryptoAuthKeybytes => _cryptoAuth.crypto_auth_keybytes();
  static String get cryptoAuthPrimitive =>
      Utf8.fromUtf8(_cryptoAuth.crypto_auth_primitive());

  static Uint8List cryptoAuth(Uint8List i, Uint8List k) {
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(k.length, cryptoAuthKeybytes,
        cryptoAuthKeybytes, 'k', 'Invalid length');

    final _out = allocate<Uint8>(count: cryptoAuthBytes);
    final _in = i.toPointer();
    final _k = k.toPointer();

    try {
      _cryptoAuth
          .crypto_auth(_out, _in, i.length, _k)
          .mustSucceed('crypto_auth');

      return _out.toList(cryptoAuthBytes);
    } finally {
      free(_out);
      free(_in);
      free(_k);
    }
  }

  static bool cryptoAuthVerify(Uint8List h, Uint8List i, Uint8List k) {
    assert(h != null);
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        h.length, cryptoAuthBytes, cryptoAuthBytes, 'h', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoAuthKeybytes,
        cryptoAuthKeybytes, 'k', 'Invalid length');

    final _h = h.toPointer();
    final _in = i.toPointer();
    final _k = k.toPointer();

    try {
      return _cryptoAuth.crypto_auth_verify(_h, _in, i.length, _k) == 0;
    } finally {
      free(_h);
      free(_in);
      free(_k);
    }
  }

  static Uint8List cryptoAuthKeygen() {
    final _k = allocate<Uint8>(count: cryptoAuthKeybytes);
    try {
      _cryptoAuth.crypto_auth_keygen(_k);
      return _k.toList(cryptoAuthKeybytes);
    } finally {
      free(_k);
    }
  }

  //
  // crypto_box
  //
  static int get cryptoBoxSeedbytes => _cryptoBox.crypto_box_seedbytes();
  static int get cryptoBoxPublickeybytes =>
      _cryptoBox.crypto_box_publickeybytes();
  static int get cryptoBoxSecretkeybytes =>
      _cryptoBox.crypto_box_secretkeybytes();
  static int get cryptoBoxNoncebytes => _cryptoBox.crypto_box_noncebytes();
  static int get cryptoBoxMacbytes => _cryptoBox.crypto_box_macbytes();
  static int get cryptoBoxMessagebytesMax =>
      _cryptoBox.crypto_box_messagebytes_max();
  static int get cryptoBoxSealbytes => _cryptoBox.crypto_box_sealbytes();
  static int get cryptoBoxBeforenmbytes =>
      _cryptoBox.crypto_box_beforenmbytes();
  static String get cryptoBoxPrimitive =>
      Utf8.fromUtf8(_cryptoBox.crypto_box_primitive());

  static Map<String, Uint8List> cryptoBoxSeedKeypair(Uint8List seed) {
    assert(seed != null);
    RangeError.checkValueInInterval(seed.length, cryptoBoxSeedbytes,
        cryptoBoxSeedbytes, 'seed', 'Invalid length');
    final _pk = allocate<Uint8>(count: cryptoBoxPublickeybytes);
    final _sk = allocate<Uint8>(count: cryptoBoxSecretkeybytes);
    final _seed = seed.toPointer();

    try {
      _cryptoBox
          .crypto_box_seed_keypair(_pk, _sk, _seed)
          .mustSucceed('crypto_box_seed_keypair');
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
      _cryptoBox.crypto_box_keypair(_pk, _sk).mustSucceed('crypto_box_keypair');
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
      _cryptoBox
          .crypto_box_easy(_c, _m, m.length, _n, _pk, _sk)
          .mustSucceed('crypto_box_easy');

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
      _cryptoBox
          .crypto_box_open_easy(_m, _c, c.length, _n, _pk, _sk)
          .mustSucceed('crypto_box_open_easy');

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
      _cryptoBox
          .crypto_box_detached(_c, _mac, _m, m.length, _n, _pk, _sk)
          .mustSucceed('crypto_box_detached');

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
      _cryptoBox
          .crypto_box_open_detached(_m, _c, _mac, c.length, _n, _pk, _sk)
          .mustSucceed('crypto_box_open_detached');

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
      _cryptoBox
          .crypto_box_beforenm(_k, _pk, _sk)
          .mustSucceed('crypto_box_beforenm');

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
      _cryptoBox
          .crypto_box_easy_afternm(_c, _m, m.length, _n, _k)
          .mustSucceed('crypto_box_easy_afternm');

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
      _cryptoBox
          .crypto_box_open_easy_afternm(_m, _c, c.length, _n, _k)
          .mustSucceed('crypto_box_open_easy_afternm');

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
      _cryptoBox
          .crypto_box_detached_afternm(_c, _mac, _m, m.length, _n, _k)
          .mustSucceed('crypto_box_detached_afternm');

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
      _cryptoBox
          .crypto_box_open_detached_afternm(_m, _c, _mac, c.length, _n, _k)
          .mustSucceed('crypto_box_open_detached_afternm');

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
      _cryptoBox
          .crypto_box_seal(_c, _m, m.length, _pk)
          .mustSucceed('crypto_box_seal');

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
      _cryptoBox
          .crypto_box_seal_open(_m, _c, c.length, _pk, _sk)
          .mustSucceed('crypto_box_seal_open');

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
  static int get cryptoGenerichashBytesMin =>
      _cryptoGenerichash.crypto_generichash_bytes_min();
  static int get cryptoGenerichashBytesMax =>
      _cryptoGenerichash.crypto_generichash_bytes_max();
  static int get cryptoGenerichashBytes =>
      _cryptoGenerichash.crypto_generichash_bytes();
  static int get cryptoGenerichashKeybytesMin =>
      _cryptoGenerichash.crypto_generichash_keybytes_min();
  static int get cryptoGenerichashKeybytesMax =>
      _cryptoGenerichash.crypto_generichash_keybytes_max();
  static int get cryptoGenerichashKeybytes =>
      _cryptoGenerichash.crypto_generichash_keybytes();
  static String get cryptoGenerichashPrimitive =>
      Utf8.fromUtf8(_cryptoGenerichash.crypto_generichash_primitive());
  static int get cryptoGenerichashStatebytes =>
      _cryptoGenerichash.crypto_generichash_statebytes();

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
      _cryptoGenerichash
          .crypto_generichash(
              _out, outlen, _in, i.length, _key, key?.length ?? 0)
          .mustSucceed('crypto_generichash');
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
      _cryptoGenerichash
          .crypto_generichash_init(_state, _key, key?.length ?? 0, outlen)
          .mustSucceed('crypto_generichash_init');
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
      _cryptoGenerichash
          .crypto_generichash_update(state, _in, i.length)
          .mustSucceed('crypto_generichash_update');
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
      _cryptoGenerichash
          .crypto_generichash_final(state, _out, outlen)
          .mustSucceed('crypto_generichash_final');
      return _out.toList(outlen);
    } finally {
      // note: caller is responsible for freeing state
      free(_out);
    }
  }

  static Uint8List cryptoGenerichashKeygen() {
    final _k = allocate<Uint8>(count: cryptoGenerichashKeybytes);
    try {
      _cryptoGenerichash.crypto_generichash_keygen(_k);
      return _k.toList(cryptoGenerichashKeybytes);
    } finally {
      free(_k);
    }
  }

  //
  // crypto_kdf
  //
  static int get cryptoKdfBytesMin => _cryptoKdf.crypto_kdf_bytes_min();
  static int get cryptoKdfBytesMax => _cryptoKdf.crypto_kdf_bytes_max();
  static int get cryptoKdfContextbytes => _cryptoKdf.crypto_kdf_contextbytes();
  static int get cryptoKdfKeybytes => _cryptoKdf.crypto_kdf_keybytes();
  static String get cryptoKdfPrimitive =>
      Utf8.fromUtf8(_cryptoKdf.crypto_kdf_primitive());

  static Uint8List cryptoKdfDeriveFromKey(
      int subkeyLen, int subkeyId, Uint8List ctx, Uint8List key) {
    assert(subkeyLen != null);
    assert(subkeyId != null);
    assert(ctx != null);
    assert(key != null);
    RangeError.checkValueInInterval(
        subkeyLen, cryptoKdfBytesMin, cryptoKdfBytesMax, 'subkeyLen');
    RangeError.checkValueInInterval(subkeyId, 0, (2 ^ 64) - 1, 'subkeyId');
    RangeError.checkValueInInterval(ctx.length, cryptoKdfContextbytes,
        cryptoKdfContextbytes, 'ctx', 'Invalid length');
    RangeError.checkValueInInterval(key.length, cryptoKdfKeybytes,
        cryptoKdfKeybytes, 'key', 'Invalid length');

    final _subkey = allocate<Uint8>(count: subkeyLen);
    final _ctx = ctx.toPointer();
    final _key = key.toPointer();

    try {
      _cryptoKdf
          .crypto_kdf_derive_from_key(_subkey, subkeyLen, subkeyId, _ctx, _key)
          .mustSucceed('crypto_kdf_derive_from_key');
      return _subkey.toList(subkeyLen);
    } finally {
      free(_subkey);
      free(_ctx);
      free(_key);
    }
  }

  static Uint8List cryptoKdfKeygen() {
    final _k = allocate<Uint8>(count: cryptoKdfKeybytes);
    try {
      _cryptoKdf.crypto_kdf_keygen(_k);
      return _k.toList(cryptoKdfKeybytes);
    } finally {
      free(_k);
    }
  }

  //
  // crypto_kx
  //
  static int get cryptoKxPublickeybytes => _cryptoKx.crypto_kx_publickeybytes();
  static int get cryptoKxSecretkeybytes => _cryptoKx.crypto_kx_secretkeybytes();
  static int get cryptoKxSeedbytes => _cryptoKx.crypto_kx_seedbytes();
  static int get cryptoKxSessionkeybytes =>
      _cryptoKx.crypto_kx_sessionkeybytes();
  static String get cryptoKxPrimitive =>
      Utf8.fromUtf8(_cryptoKx.crypto_kx_primitive());

  static Map<String, Uint8List> cryptoKxSeedKeypair(Uint8List seed) {
    assert(seed != null);
    RangeError.checkValueInInterval(seed.length, cryptoKxSeedbytes,
        cryptoKxSeedbytes, 'seed', 'Invalid length');
    final _pk = allocate<Uint8>(count: cryptoKxPublickeybytes);
    final _sk = allocate<Uint8>(count: cryptoKxSecretkeybytes);
    final _seed = seed.toPointer();

    try {
      _cryptoKx
          .crypto_kx_seed_keypair(_pk, _sk, _seed)
          .mustSucceed('crypto_kx_seed_keypair');
      return {
        Names.pk: _pk.toList(cryptoKxPublickeybytes),
        Names.sk: _sk.toList(cryptoKxSecretkeybytes)
      };
    } finally {
      free(_pk);
      free(_sk);
      free(_seed);
    }
  }

  static Map<String, Uint8List> cryptoKxKeypair() {
    final _pk = allocate<Uint8>(count: cryptoKxPublickeybytes);
    final _sk = allocate<Uint8>(count: cryptoKxSecretkeybytes);

    try {
      _cryptoKx.crypto_kx_keypair(_pk, _sk).mustSucceed('crypto_kx_keypair');
      return {
        Names.pk: _pk.toList(cryptoKxPublickeybytes),
        Names.sk: _sk.toList(cryptoKxSecretkeybytes)
      };
    } finally {
      free(_pk);
      free(_sk);
    }
  }

  static Map<String, Uint8List> cryptoKxClientSessionKeys(
      Uint8List clientPk, Uint8List clientSk, Uint8List serverPk) {
    assert(clientPk != null);
    assert(clientSk != null);
    assert(serverPk != null);
    RangeError.checkValueInInterval(clientPk.length, cryptoKxPublickeybytes,
        cryptoKxPublickeybytes, 'clientPk', 'Invalid length');
    RangeError.checkValueInInterval(clientSk.length, cryptoKxSecretkeybytes,
        cryptoKxSecretkeybytes, 'clientSk', 'Invalid length');
    RangeError.checkValueInInterval(serverPk.length, cryptoKxPublickeybytes,
        cryptoKxPublickeybytes, 'serverPk', 'Invalid length');

    final _rx = allocate<Uint8>(count: cryptoKxSessionkeybytes);
    final _tx = allocate<Uint8>(count: cryptoKxSessionkeybytes);
    final _clientPk = clientPk.toPointer();
    final _clientSk = clientSk.toPointer();
    final _serverPk = serverPk.toPointer();

    try {
      _cryptoKx
          .crypto_kx_client_session_keys(
              _rx, _tx, _clientPk, _clientSk, _serverPk)
          .mustSucceed('crypto_kx_client_session_keys');

      return {
        Names.rx: _rx.toList(cryptoKxSessionkeybytes),
        Names.tx: _tx.toList(cryptoKxSessionkeybytes)
      };
    } finally {
      free(_rx);
      free(_tx);
      free(_clientPk);
      free(_clientSk);
      free(_serverPk);
    }
  }

  static Map<String, Uint8List> cryptoKxServerSessionKeys(
      Uint8List serverPk, Uint8List serverSk, Uint8List clientPk) {
    assert(serverPk != null);
    assert(serverSk != null);
    assert(clientPk != null);
    RangeError.checkValueInInterval(serverPk.length, cryptoKxPublickeybytes,
        cryptoKxPublickeybytes, 'serverPk', 'Invalid length');
    RangeError.checkValueInInterval(serverSk.length, cryptoKxSecretkeybytes,
        cryptoKxSecretkeybytes, 'serverSk', 'Invalid length');
    RangeError.checkValueInInterval(clientPk.length, cryptoKxPublickeybytes,
        cryptoKxPublickeybytes, 'clientPk', 'Invalid length');

    final _rx = allocate<Uint8>(count: cryptoKxSessionkeybytes);
    final _tx = allocate<Uint8>(count: cryptoKxSessionkeybytes);
    final _serverPk = serverPk.toPointer();
    final _serverSk = serverSk.toPointer();
    final _clientPk = clientPk.toPointer();

    try {
      _cryptoKx
          .crypto_kx_server_session_keys(
              _rx, _tx, _serverPk, _serverSk, _clientPk)
          .mustSucceed('crypto_kx_server_session_keys');

      return {
        Names.rx: _rx.toList(cryptoKxSessionkeybytes),
        Names.tx: _tx.toList(cryptoKxSessionkeybytes)
      };
    } finally {
      free(_rx);
      free(_tx);
      free(_serverPk);
      free(_serverSk);
      free(_clientPk);
    }
  }

  //
  // crypto_onetimeauth
  //
  static int get cryptoOnetimeauthStatebytes =>
      _cryptoOnetimeauth.crypto_onetimeauth_statebytes();
  static int get cryptoOnetimeauthBytes =>
      _cryptoOnetimeauth.crypto_onetimeauth_bytes();
  static int get cryptoOnetimeauthKeybytes =>
      _cryptoOnetimeauth.crypto_onetimeauth_keybytes();
  static String get cryptoOnetimeauthPrimitive =>
      Utf8.fromUtf8(_cryptoOnetimeauth.crypto_onetimeauth_primitive());

  static Uint8List cryptoOnetimeauth(Uint8List i, Uint8List k) {
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(k.length, cryptoOnetimeauthKeybytes,
        cryptoOnetimeauthKeybytes, 'k', 'Invalid length');

    final _out = allocate<Uint8>(count: cryptoOnetimeauthBytes);
    final _in = i.toPointer();
    final _k = k.toPointer();
    try {
      _cryptoOnetimeauth
          .crypto_onetimeauth(_out, _in, i.length, _k)
          .mustSucceed('crypto_onetimeauth');
      return _out.toList(cryptoOnetimeauthBytes);
    } finally {
      free(_out);
      free(_in);
      free(_k);
    }
  }

  static bool cryptoOnetimeauthVerify(Uint8List h, Uint8List i, Uint8List k) {
    assert(h != null);
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(h.length, cryptoOnetimeauthBytes,
        cryptoOnetimeauthBytes, 'h', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoOnetimeauthKeybytes,
        cryptoOnetimeauthKeybytes, 'k', 'Invalid length');

    final _h = h.toPointer();
    final _in = i.toPointer();
    final _k = k.toPointer();
    try {
      return _cryptoOnetimeauth.crypto_onetimeauth_verify(
              _h, _in, i.length, _k) ==
          0;
    } finally {
      free(_h);
      free(_in);
      free(_k);
    }
  }

  static Pointer<Uint8> cryptoOnetimeauthInit(Uint8List key) {
    assert(key != null);
    RangeError.checkValueInInterval(key.length, cryptoOnetimeauthKeybytes,
        cryptoOnetimeauthKeybytes, 'key', 'Invalid length');

    final _state = allocate<Uint8>(count: cryptoOnetimeauthStatebytes);
    final _k = key.toPointer();
    try {
      _cryptoOnetimeauth
          .crypto_onetimeauth_init(_state, _k)
          .mustSucceed('crypto_onetimeauth_init');
      return _state;
    } finally {
      free(_k);
    }
  }

  static void cryptoOnetimeauthUpdate(Pointer<Uint8> state, Uint8List i) {
    assert(state != null);
    assert(i != null);

    final _in = i.toPointer();
    try {
      _cryptoOnetimeauth
          .crypto_onetimeauth_update(state, _in, i.length)
          .mustSucceed('crypto_onetimeauth_update');
    } finally {
      free(_in);
    }
  }

  static Uint8List cryptoOnetimeauthFinal(Pointer<Uint8> state) {
    assert(state != null);

    final _out = allocate<Uint8>(count: cryptoOnetimeauthBytes);
    try {
      _cryptoOnetimeauth.crypto_onetimeauth_final(state, _out);
      return _out.toList(cryptoOnetimeauthBytes);
    } finally {
      free(_out);
    }
  }

  static Uint8List cryptoOnetimeauthKeygen() {
    final _k = allocate<Uint8>(count: cryptoOnetimeauthKeybytes);
    try {
      _cryptoOnetimeauth.crypto_onetimeauth_keygen(_k);
      return _k.toList(cryptoOnetimeauthKeybytes);
    } finally {
      free(_k);
    }
  }

  //
  // crypto_pwhash
  //
  static int get cryptoPwhashAlgArgon2i13 =>
      _cryptoPwhash.crypto_pwhash_alg_argon2i13();
  static int get cryptoPwhashAlgArgon2id13 =>
      _cryptoPwhash.crypto_pwhash_alg_argon2id13();
  static int get cryptoPwhashAlgDefault =>
      _cryptoPwhash.crypto_pwhash_alg_default();
  static int get cryptoPwhashBytesMin =>
      _cryptoPwhash.crypto_pwhash_bytes_min();
  static int get cryptoPwhashBytesMax =>
      _cryptoPwhash.crypto_pwhash_bytes_max();
  static int get cryptoPwhashPasswdMin =>
      _cryptoPwhash.crypto_pwhash_passwd_min();
  static int get cryptoPwhashPasswdMax =>
      _cryptoPwhash.crypto_pwhash_passwd_max();
  static int get cryptoPwhashSaltbytes =>
      _cryptoPwhash.crypto_pwhash_saltbytes();
  static int get cryptoPwhashStrbytes => _cryptoPwhash.crypto_pwhash_strbytes();
  static String get cryptoPwhashStrprefix =>
      Utf8.fromUtf8(_cryptoPwhash.crypto_pwhash_strprefix());
  static int get cryptoPwhashOpslimitMin =>
      _cryptoPwhash.crypto_pwhash_opslimit_min();
  static int get cryptoPwhashOpslimitMax =>
      _cryptoPwhash.crypto_pwhash_opslimit_max();
  static int get cryptoPwhashMemlimitMin =>
      _cryptoPwhash.crypto_pwhash_memlimit_min();
  static int get cryptoPwhashMemlimitMax =>
      _cryptoPwhash.crypto_pwhash_memlimit_max();
  static int get cryptoPwhashOpslimitInteractive =>
      _cryptoPwhash.crypto_pwhash_opslimit_interactive();
  static int get cryptoPwhashMemlimitInteractive =>
      _cryptoPwhash.crypto_pwhash_memlimit_interactive();
  static int get cryptoPwhashOpslimitModerate =>
      _cryptoPwhash.crypto_pwhash_opslimit_moderate();
  static int get cryptoPwhashMemlimitModerate =>
      _cryptoPwhash.crypto_pwhash_memlimit_moderate();
  static int get cryptoPwhashOpslimitSensitive =>
      _cryptoPwhash.crypto_pwhash_opslimit_sensitive();
  static int get cryptoPwhashMemlimitSensitive =>
      _cryptoPwhash.crypto_pwhash_memlimit_sensitive();
  static String get cryptoPwhashPrimitive =>
      Utf8.fromUtf8(_cryptoPwhash.crypto_pwhash_primitive());

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
      _cryptoPwhash
          .crypto_pwhash(_out, outlen, _passwd, passwd.length, _salt, opslimit,
              memlimit, alg)
          .mustSucceed('crypto_pwhash');

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
      _cryptoPwhash
          .crypto_pwhash_str(_out, _passwd, passwd.length, opslimit, memlimit)
          .mustSucceed('crypto_pwhash_str');
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
      _cryptoPwhash
          .crypto_pwhash_str_alg(
              _out, _passwd, passwd.length, opslimit, memlimit, alg)
          .mustSucceed('crypto_pwhash_str_alg');
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
      return _cryptoPwhash.crypto_pwhash_str_verify(
          _str, _passwd, passwd.length);
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
      return _cryptoPwhash.crypto_pwhash_str_needs_rehash(
          _str, opslimit, memlimit);
    } finally {
      free(_str);
    }
  }

  //
  // crypto_scalarmult
  //
  static int get cryptoScalarmultBytes =>
      _cryptoScalarmult.crypto_scalarmult_bytes();
  static int get cryptoScalarmultScalarbytes =>
      _cryptoScalarmult.crypto_scalarmult_scalarbytes();
  static int get cryptoScalarmultCurve25519Bytes =>
      _cryptoScalarmult.crypto_scalarmult_curve25519_bytes();
  static String get cryptoScalarmultPrimitive =>
      Utf8.fromUtf8(_cryptoScalarmult.crypto_scalarmult_primitive());

  static Uint8List cryptoScalarmultBase(Uint8List n) {
    assert(n != null);
    RangeError.checkValueInInterval(n.length, cryptoScalarmultScalarbytes,
        cryptoScalarmultScalarbytes, 'n', 'Invalid length');

    final _q = allocate<Uint8>(count: cryptoScalarmultBytes);
    final _n = n.toPointer();
    try {
      _cryptoScalarmult
          .crypto_scalarmult_base(_q, _n)
          .mustSucceed('crypto_scalarmult_base');
      return _q.toList(cryptoScalarmultBytes);
    } finally {
      free(_q);
      free(_n);
    }
  }

  static Uint8List cryptoScalarmult(Uint8List n, Uint8List p) {
    assert(n != null);
    assert(p != null);
    RangeError.checkValueInInterval(n.length, cryptoScalarmultScalarbytes,
        cryptoScalarmultScalarbytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(p.length, cryptoScalarmultBytes,
        cryptoScalarmultBytes, 'p', 'Invalid length');

    final _q = allocate<Uint8>(count: cryptoScalarmultBytes);
    final _n = n.toPointer();
    final _p = p.toPointer();
    try {
      _cryptoScalarmult
          .crypto_scalarmult(_q, _n, _p)
          .mustSucceed('crypto_scalarmult');
      return _q.toList(cryptoScalarmultBytes);
    } finally {
      free(_q);
      free(_n);
      free(_p);
    }
  }

  //
  // crypto_secretbox
  //
  static int get cryptoSecretboxKeybytes =>
      _cryptoSecretbox.crypto_secretbox_keybytes();
  static int get cryptoSecretboxNoncebytes =>
      _cryptoSecretbox.crypto_secretbox_noncebytes();
  static int get cryptoSecretboxMacbytes =>
      _cryptoSecretbox.crypto_secretbox_macbytes();
  static int get cryptoSecretboxMessagebytesMax =>
      _cryptoSecretbox.crypto_secretbox_messagebytes_max();
  static String get cryptoSecretboxPrimitive =>
      Utf8.fromUtf8(_cryptoSecretbox.crypto_secretbox_primitive());

  static Uint8List cryptoSecretboxEasy(Uint8List m, Uint8List n, Uint8List k) {
    assert(m != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, cryptoSecretboxNoncebytes,
        cryptoSecretboxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoSecretboxKeybytes,
        cryptoSecretboxKeybytes, 'k', 'Invalid length');

    final _c = allocate<Uint8>(count: m.length + cryptoSecretboxMacbytes);
    final _m = m.toPointer();
    final _n = n.toPointer();
    final _k = k.toPointer();

    try {
      _cryptoSecretbox
          .crypto_secretbox_easy(_c, _m, m.length, _n, _k)
          .mustSucceed('crypto_secretbox_easy');
      return _c.toList(m.length + cryptoSecretboxMacbytes);
    } finally {
      free(_c);
      free(_m);
      free(_n);
      free(_k);
    }
  }

  static Uint8List cryptoSecretboxOpenEasy(
      Uint8List c, Uint8List n, Uint8List k) {
    assert(c != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, cryptoSecretboxNoncebytes,
        cryptoSecretboxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoSecretboxKeybytes,
        cryptoSecretboxKeybytes, 'k', 'Invalid length');

    final _m = allocate<Uint8>(count: c.length - cryptoSecretboxMacbytes);
    final _c = c.toPointer();
    final _n = n.toPointer();
    final _k = k.toPointer();

    try {
      _cryptoSecretbox
          .crypto_secretbox_open_easy(_m, _c, c.length, _n, _k)
          .mustSucceed('crypto_secretbox_open_easy');
      return _m.toList(c.length - cryptoSecretboxMacbytes);
    } finally {
      free(_m);
      free(_c);
      free(_n);
      free(_k);
    }
  }

  static Map<String, Uint8List> cryptoSecretboxDetached(
      Uint8List m, Uint8List n, Uint8List k) {
    assert(m != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, cryptoSecretboxNoncebytes,
        cryptoSecretboxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoSecretboxKeybytes,
        cryptoSecretboxKeybytes, 'k', 'Invalid length');

    final _c = allocate<Uint8>(count: m.length);
    final _mac = allocate<Uint8>(count: cryptoSecretboxMacbytes);
    final _m = m.toPointer();
    final _n = n.toPointer();
    final _k = k.toPointer();

    try {
      _cryptoSecretbox
          .crypto_secretbox_detached(_c, _mac, _m, m.length, _n, _k)
          .mustSucceed('crypto_secretbox_detached');
      return {
        Names.c: _c.toList(m.length),
        Names.mac: _mac.toList(cryptoSecretboxMacbytes)
      };
    } finally {
      free(_c);
      free(_mac);
      free(_m);
      free(_n);
      free(_k);
    }
  }

  static Uint8List cryptoSecretboxOpenDetached(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List k) {
    assert(c != null);
    assert(mac != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(mac.length, cryptoSecretboxMacbytes,
        cryptoSecretboxMacbytes, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(n.length, cryptoSecretboxNoncebytes,
        cryptoSecretboxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoSecretboxKeybytes,
        cryptoSecretboxKeybytes, 'k', 'Invalid length');

    final _m = allocate<Uint8>(count: c.length);
    final _mac = mac.toPointer();
    final _c = c.toPointer();
    final _n = n.toPointer();
    final _k = k.toPointer();

    try {
      _cryptoSecretbox
          .crypto_secretbox_open_detached(_m, _c, _mac, c.length, _n, _k)
          .mustSucceed('crypto_secretbox_open_detached');
      return _m.toList(c.length);
    } finally {
      free(_m);
      free(_mac);
      free(_c);
      free(_n);
      free(_k);
    }
  }

  static Uint8List cryptoSecretboxKeygen() {
    final _k = allocate<Uint8>(count: cryptoSecretboxKeybytes);
    try {
      _cryptoSecretbox.crypto_secretbox_keygen(_k);
      return _k.toList(cryptoSecretboxKeybytes);
    } finally {
      free(_k);
    }
  }

  //
  // crypto_shorthash
  //
  static int get cryptoShorthashBytes =>
      _cryptoShorthash.crypto_shorthash_bytes();
  static int get cryptoShorthashKeybytes =>
      _cryptoShorthash.crypto_shorthash_keybytes();
  static String get cryptoShorthashPrimitive =>
      Utf8.fromUtf8(_cryptoShorthash.crypto_shorthash_primitive());

  static Uint8List cryptoShorthash(Uint8List i, Uint8List k) {
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(k.length, cryptoShorthashKeybytes,
        cryptoShorthashKeybytes, 'k', 'Invalid length');

    final _out = allocate<Uint8>(count: cryptoShorthashBytes);
    final _in = i.toPointer();
    final _k = k.toPointer();
    try {
      _cryptoShorthash
          .crypto_shorthash(_out, _in, i.length, _k)
          .mustSucceed('crypto_shorthash');
      return _out.toList(cryptoShorthashBytes);
    } finally {
      free(_out);
      free(_k);
    }
  }

  static Uint8List cryptoShorthashKeygen() {
    final _k = allocate<Uint8>(count: cryptoShorthashKeybytes);
    try {
      _cryptoShorthash.crypto_shorthash_keygen(_k);
      return _k.toList(cryptoShorthashKeybytes);
    } finally {
      free(_k);
    }
  }

  //
  // crypto_sign
  //
  static int get cryptoSignStatebytes => _cryptoSign.crypto_sign_statebytes();
  static int get cryptoSignBytes => _cryptoSign.crypto_sign_bytes();
  static int get cryptoSignSeedbytes => _cryptoSign.crypto_sign_seedbytes();
  static int get cryptoSignPublickeybytes =>
      _cryptoSign.crypto_sign_publickeybytes();
  static int get cryptoSignSecretkeybytes =>
      _cryptoSign.crypto_sign_secretkeybytes();
  static int get cryptoSignMessagebytesMax =>
      _cryptoSign.crypto_sign_messagebytes_max();
  static int get cryptoSignEd25519Publickeybytes =>
      _cryptoSign.crypto_sign_ed25519_publickeybytes();
  static int get cryptoSignEd25519Secretkeybytes =>
      _cryptoSign.crypto_sign_ed25519_secretkeybytes();
  static String get cryptoSignPrimitive =>
      Utf8.fromUtf8(_cryptoSign.crypto_sign_primitive());

  static Map<String, Uint8List> cryptoSignSeedKeypair(Uint8List seed) {
    assert(seed != null);
    RangeError.checkValueInInterval(seed.length, cryptoSignSeedbytes,
        cryptoSignSeedbytes, 'seed', 'Invalid length');
    final _pk = allocate<Uint8>(count: cryptoSignPublickeybytes);
    final _sk = allocate<Uint8>(count: cryptoSignSecretkeybytes);
    final _seed = seed.toPointer();

    try {
      _cryptoSign
          .crypto_sign_seed_keypair(_pk, _sk, _seed)
          .mustSucceed('crypto_sign_seed_keypair');
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
      _cryptoSign
          .crypto_sign_keypair(_pk, _sk)
          .mustSucceed('crypto_sign_keypair');
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
      _cryptoSign
          .crypto_sign(_sm, _smlenP, _m, m.length, _sk)
          .mustSucceed('crypto_sign');
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
      _cryptoSign
          .crypto_sign_open(_m, _mlenP, _sm, sm.length, _pk)
          .mustSucceed('crypto_sign_open');
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
      _cryptoSign
          .crypto_sign_detached(_sig, _siglenP, _m, m.length, _sk)
          .mustSucceed('crypto_sign_detached');
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
      return _cryptoSign.crypto_sign_verify_detached(_sig, _m, m.length, _pk);
    } finally {
      free(_sig);
      free(_m);
      free(_pk);
    }
  }

  static Pointer<Uint8> cryptoSignInit() {
    final _state = allocate<Uint8>(count: cryptoSignStatebytes);
    _cryptoSign.crypto_sign_init(_state).mustSucceed('crypto_sign_init');
    return _state;
  }

  static void cryptoSignUpdate(Pointer<Uint8> state, Uint8List m) {
    assert(state != null);
    assert(m != null);

    final _m = m.toPointer();
    try {
      _cryptoSign
          .crypto_sign_update(state, _m, m.length)
          .mustSucceed('crypto_sign_update');
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
      _cryptoSign
          .crypto_sign_final_create(state, _sig, _siglenP, _sk)
          .mustSucceed('crypto_sign_final_create');
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
      return _cryptoSign.crypto_sign_final_verify(state, _sig, _pk);
    } finally {
      // note: caller is responsible for freeing state
      free(_sig);
      free(_pk);
    }
  }

  static Uint8List cryptoSignEd25519SkToSeed(Uint8List sk) {
    assert(sk != null);
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final _seed = allocate<Uint8>(count: cryptoSignSeedbytes);
    final _sk = sk.toPointer();
    try {
      _cryptoSign
          .crypto_sign_ed25519_sk_to_seed(_seed, _sk)
          .mustSucceed('crypto_sign_ed25519_sk_to_seed');
      return _seed.toList(cryptoSignSeedbytes);
    } finally {
      free(_seed);
      free(_sk);
    }
  }

  static Uint8List cryptoSignEd25519SkToPk(Uint8List sk) {
    assert(sk != null);
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final _pk = allocate<Uint8>(count: cryptoSignPublickeybytes);
    final _sk = sk.toPointer();
    try {
      _cryptoSign
          .crypto_sign_ed25519_sk_to_pk(_pk, _sk)
          .mustSucceed('crypto_sign_ed25519_sk_to_pk');
      return _pk.toList(cryptoSignPublickeybytes);
    } finally {
      free(_pk);
      free(_sk);
    }
  }

  static Uint8List cryptoSignEd25519PkToCurve25519(Uint8List ed25519Pk) {
    assert(ed25519Pk != null);
    RangeError.checkValueInInterval(
        ed25519Pk.length,
        cryptoSignEd25519Publickeybytes,
        cryptoSignEd25519Publickeybytes,
        'ed25519Pk',
        'Invalid length');

    final _curve25519Pk =
        allocate<Uint8>(count: cryptoScalarmultCurve25519Bytes);
    final _ed25519Pk = ed25519Pk.toPointer();
    try {
      _cryptoSign
          .crypto_sign_ed25519_pk_to_curve25519(_curve25519Pk, _ed25519Pk)
          .mustSucceed('crypto_sign_ed25519_pk_to_curve25519');
      return _curve25519Pk.toList(cryptoScalarmultCurve25519Bytes);
    } finally {
      free(_curve25519Pk);
      free(_ed25519Pk);
    }
  }

  static Uint8List cryptoSignEd25519SkToCurve25519(Uint8List ed25519Sk) {
    assert(ed25519Sk != null);
    RangeError.checkValueInInterval(
        ed25519Sk.length,
        cryptoSignEd25519Secretkeybytes,
        cryptoSignEd25519Secretkeybytes,
        'ed25519Sk',
        'Invalid length');

    final _curve25519Pk =
        allocate<Uint8>(count: cryptoScalarmultCurve25519Bytes);
    final _ed25519Sk = ed25519Sk.toPointer();
    try {
      _cryptoSign
          .crypto_sign_ed25519_sk_to_curve25519(_curve25519Pk, _ed25519Sk)
          .mustSucceed('crypto_sign_ed25519_sk_to_curve25519');
      return _curve25519Pk.toList(cryptoScalarmultCurve25519Bytes);
    } finally {
      free(_curve25519Pk);
      free(_ed25519Sk);
    }
  }

  //
  // randombytes
  //
  static int get randombytesSeedbytes => _randombytes.randombytes_seedbytes();

  static Uint8List randombytesBuf(int size) {
    assert(size != null);
    RangeError.checkNotNegative(size);

    final _buf = allocate<Uint8>(count: size);
    try {
      _randombytes.randombytes_buf(_buf, size);
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
      _randombytes.randombytes_buf_deterministic(_buf, size, _seed);
      return _buf.toList(size);
    } finally {
      free(_buf);
      free(_seed);
    }
  }

  static int randombytesRandom() => _randombytes.randombytes_random();

  static int randombytesUniform(int upperBound) {
    assert(upperBound != null);
    RangeError.checkNotNegative(upperBound);

    return _randombytes.randombytes_uniform(upperBound);
  }

  static void randombytesStir() => _randombytes.randombytes_stir();
  static void randombytesClose() => _randombytes.randombytes_close();

  static String get randombytesImplementationName =>
      Utf8.fromUtf8(_randombytes.randombytes_implementation_name());

  //
  // sodium
  //
  static void sodiumInit() {
    if (_sodium.sodium_init() == -1) {
      throw SodiumException('Libsodium initialization failed');
    }
  }

  static String get sodiumVersionString =>
      Utf8.fromUtf8(_sodium.sodium_version_string());
  static int get sodiumLibraryVersionMajor =>
      _sodium.sodium_library_version_major();
  static int get sodiumLibraryVersionMinor =>
      _sodium.sodium_library_version_minor();
  static int get sodiumLibraryMinimal => _sodium.sodium_library_minimal();
}

class _CryptoAead {
  final String name;
  final CryptoAeadBindings _bindings;
  _CryptoAead(this.name) : _bindings = CryptoAeadBindings(name);
  _CryptoAead.chacha20poly1305() : this('crypto_aead_chacha20poly1305');
  _CryptoAead.chacha20poly1305Ietf()
      : this('crypto_aead_chacha20poly1305_ietf');
  _CryptoAead.xchacha20poly1305Ietf()
      : this('crypto_aead_xchacha20poly1305_ietf');

  int get keybytes => _bindings.keybytes();
  int get nsecbytes => _bindings.nsecbytes();
  int get npubbytes => _bindings.npubbytes();
  int get abytes => _bindings.abytes();
  int get messagebytesMax => _bindings.messagebytes_max();

  Uint8List encrypt(
      Uint8List m, Uint8List ad, Uint8List nsec, Uint8List npub, Uint8List k) {
    assert(m != null);
    assert(nsec == null); // yes, nsec must be null
    assert(npub != null);
    assert(k != null);

    RangeError.checkValueInInterval(
        npub.length, npubbytes, npubbytes, 'npub', 'Invalid length');
    RangeError.checkValueInInterval(
        k.length, keybytes, keybytes, 'k', 'Invalid length');

    final _c = allocate<Uint8>(count: m.length + abytes);
    final _clenP = allocate<Uint64>(count: 1);
    final _m = m.toPointer();
    final _ad = ad.toPointer();
    final _adlen = ad?.length ?? 0;
    final _npub = npub.toPointer();
    final _k = k.toPointer();
    try {
      _bindings
          .encrypt(_c, _clenP, _m, m.length, _ad, _adlen,
              Pointer.fromAddress(0), _npub, _k)
          .mustSucceed('${name}_encrypt');
      return _c.toList(_clenP[0]);
    } finally {
      free(_c);
      free(_clenP);
      free(_m);
      free(_ad);
      free(_npub);
      free(_k);
    }
  }

  Uint8List decrypt(
      Uint8List nsec, Uint8List c, Uint8List ad, Uint8List npub, Uint8List k) {
    assert(nsec == null); // yes, nsec must be null
    assert(c != null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length, npubbytes, npubbytes, 'npub', 'Invalid length');
    RangeError.checkValueInInterval(
        k.length, keybytes, keybytes, 'k', 'Invalid length');

    final _m = allocate<Uint8>(count: c.length - abytes);
    final _mlenP = allocate<Uint64>(count: 1);
    final _c = c.toPointer();
    final _ad = ad.toPointer();
    final _adlen = ad?.length ?? 0;
    final _npub = npub.toPointer();
    final _k = k.toPointer();
    try {
      _bindings
          .decrypt(_m, _mlenP, Pointer.fromAddress(0), _c, c.length, _ad,
              _adlen, _npub, _k)
          .mustSucceed('${name}_decrypt');
      return _m.toList(_mlenP[0]);
    } finally {
      free(_m);
      free(_mlenP);
      free(_c);
      free(_ad);
      free(_npub);
      free(_k);
    }
  }

  Map<String, Uint8List> encryptDetached(
      Uint8List m, Uint8List ad, Uint8List nsec, Uint8List npub, Uint8List k) {
    assert(m != null);
    assert(nsec == null); // yes, nsec must be null
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length, npubbytes, npubbytes, 'npub', 'Invalid length');
    RangeError.checkValueInInterval(
        k.length, keybytes, keybytes, 'k', 'Invalid length');

    final _c = allocate<Uint8>(count: m.length);
    final _mac = allocate<Uint8>(count: abytes);
    final _maclenP = allocate<Uint64>(count: 1);
    final _m = m.toPointer();
    final _ad = ad.toPointer();
    final _adlen = ad?.length ?? 0;
    final _npub = npub.toPointer();
    final _k = k.toPointer();
    try {
      _bindings
          .encrypt_detached(_c, _mac, _maclenP, _m, m.length, _ad, _adlen,
              Pointer.fromAddress(0), _npub, _k)
          .mustSucceed('${name}_encrypt_detached');
      return {
        Names.c: _c.toList(m.length),
        Names.mac: _mac.toList(_maclenP[0])
      };
    } finally {
      free(_c);
      free(_mac);
      free(_maclenP);
      free(_m);
      free(_ad);
      free(_npub);
      free(_k);
    }
  }

  Uint8List decryptDetached(Uint8List nsec, Uint8List c, Uint8List mac,
      Uint8List ad, Uint8List npub, Uint8List k) {
    assert(nsec == null); // yes, nsec must be null
    assert(c != null);
    assert(mac != null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        mac.length, abytes, abytes, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(
        npub.length, npubbytes, npubbytes, 'npub', 'Invalid length');
    RangeError.checkValueInInterval(
        k.length, keybytes, keybytes, 'k', 'Invalid length');

    final _m = allocate<Uint8>(count: c.length);
    final _c = c.toPointer();
    final _mac = mac.toPointer();
    final _ad = ad.toPointer();
    final _adlen = ad?.length ?? 0;
    final _npub = npub.toPointer();
    final _k = k.toPointer();
    try {
      _bindings
          .decrypt_detached(_m, Pointer.fromAddress(0), _c, c.length, _mac, _ad,
              _adlen, _npub, _k)
          .mustSucceed('${name}_decrypt_detached');
      return _m.toList(c.length);
    } finally {
      free(_m);
      free(_c);
      free(_mac);
      free(_ad);
      free(_npub);
      free(_k);
    }
  }

  Uint8List keygen() {
    final _k = allocate<Uint8>(count: keybytes);
    try {
      _bindings.keygen(_k);
      return _k.toList(keybytes);
    } finally {
      free(_k);
    }
  }
}
