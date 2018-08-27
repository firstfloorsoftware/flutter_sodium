import 'dart:async';
import 'dart:typed_data';
import 'package:flutter/services.dart';
import 'src/constants.dart';
export 'src/cha_cha20_poly1305.dart';
export 'src/cha_cha20_poly1305_ietf.dart';
export 'src/constants.dart';
export 'src/crypto_auth.dart';
export 'src/crypto_box.dart';
export 'src/crypto_sign.dart';
export 'src/detached_cipher.dart';
export 'src/generic_hash.dart';
export 'src/key_derivation.dart';
export 'src/key_exchange.dart';
export 'src/key_pair.dart';
export 'src/onetime_auth.dart';
export 'src/password_hash.dart';
export 'src/random_bytes.dart';
export 'src/scalar_mult.dart';
export 'src/sealed_box.dart';
export 'src/secret_box.dart';
export 'src/session_keys.dart';
export 'src/short_hash.dart';
export 'src/x_cha_cha20_poly1305_ietf.dart';

/// Sodium is a modern, easy-to-use software library for encryption, decryption, signatures, password hashing and more.
///
/// This class provides a 1:1 mapping of Dart to native libsodium API functions. You can use this
/// low-level API directly, or choose to use the more Dart-friendly higher level API.
class Sodium {
  static const MethodChannel _channel = const MethodChannel('flutter_sodium');

  //
  // crypto_aead_chacha20poly1305
  //
  /// Encrypts a message with optional additional data, a key and a nonce.
  static Future<Uint8List> cryptoAeadChacha20poly1305Encrypt(
      Uint8List m, Uint8List ad, Uint8List nsec, Uint8List npub, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(nsec == null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_chacha20poly1305_NPUBBYTES,
        crypto_aead_chacha20poly1305_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_chacha20poly1305_KEYBYTES,
        crypto_aead_chacha20poly1305_KEYBYTES,
        'k',
        'Invalid length');

    final Uint8List c = await _channel.invokeMethod(
        'crypto_aead_chacha20poly1305_encrypt', {
      'm': m,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return c;
  }

  /// Verifies and decrypts a cipher text produced by encrypt.
  static Future<Uint8List> cryptoAeadChacha20poly1305Decrypt(
      Uint8List nsec, Uint8List c, Uint8List ad, Uint8List npub, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(nsec == null);
    assert(c != null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_chacha20poly1305_NPUBBYTES,
        crypto_aead_chacha20poly1305_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_chacha20poly1305_KEYBYTES,
        crypto_aead_chacha20poly1305_KEYBYTES,
        'k',
        'Invalid length');

    final Uint8List m = await _channel.invokeMethod(
        'crypto_aead_chacha20poly1305_decrypt', {
      'c': c,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return m;
  }

  /// Encrypts a message with optional additional data, a key and a nonce. Returns a ciphertext and mac.
  static Future<Map<String, Uint8List>>
      cryptoAeadChacha20poly1305EncryptDetached(Uint8List m, Uint8List ad,
          Uint8List nsec, Uint8List npub, Uint8List k,
          {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(nsec == null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_chacha20poly1305_NPUBBYTES,
        crypto_aead_chacha20poly1305_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_chacha20poly1305_KEYBYTES,
        crypto_aead_chacha20poly1305_KEYBYTES,
        'k',
        'Invalid length');

    final Map result = await _channel.invokeMethod(
        'crypto_aead_chacha20poly1305_encrypt_detached', {
      'm': m,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return result.cast<String, Uint8List>();
  }

  /// Verifies and decrypts a cipher text and mac produced by encrypt detached.
  static Future<Uint8List> cryptoAeadChacha20poly1305DecryptDetached(
      Uint8List nsec,
      Uint8List c,
      Uint8List mac,
      Uint8List ad,
      Uint8List npub,
      Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(nsec == null);
    assert(c != null);
    assert(mac != null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        mac.length,
        crypto_aead_chacha20poly1305_ABYTES,
        crypto_aead_chacha20poly1305_ABYTES,
        'mac',
        'Invalid length');
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_chacha20poly1305_NPUBBYTES,
        crypto_aead_chacha20poly1305_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_chacha20poly1305_KEYBYTES,
        crypto_aead_chacha20poly1305_KEYBYTES,
        'k',
        'Invalid length');

    final Uint8List m = await _channel
        .invokeMethod('crypto_aead_chacha20poly1305_decrypt_detached', {
      'c': c,
      'mac': mac,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return m;
  }

  /// Generates a random key.
  static Future<Uint8List> cryptoAeadChacha20poly1305Keygen(
      {bool useBackgroundThread = false}) async {
    final Uint8List k = await _channel.invokeMethod(
        'crypto_aead_chacha20poly1305_keygen',
        {'bgThread': useBackgroundThread});
    return k;
  }

  //
  // crypto_aead_chacha20poly1305_ietf
  //
  /// Encrypts a message with optional additional data, a key and a nonce.
  static Future<Uint8List> cryptoAeadChacha20poly1305IetfEncrypt(
      Uint8List m, Uint8List ad, Uint8List nsec, Uint8List npub, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(nsec == null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        'k',
        'Invalid length');

    final Uint8List c = await _channel.invokeMethod(
        'crypto_aead_chacha20poly1305_ietf_encrypt', {
      'm': m,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return c;
  }

  /// Verifies and decrypts a cipher text produced by encrypt.
  static Future<Uint8List> cryptoAeadChacha20poly1305IetfDecrypt(
      Uint8List nsec, Uint8List c, Uint8List ad, Uint8List npub, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(nsec == null);
    assert(c != null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        'k',
        'Invalid length');

    final Uint8List m = await _channel.invokeMethod(
        'crypto_aead_chacha20poly1305_ietf_decrypt', {
      'c': c,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return m;
  }

  /// Encrypts a message with optional additional data, a key and a nonce. Returns a ciphertext and mac.
  static Future<Map<String, Uint8List>>
      cryptoAeadChacha20poly1305IetfEncryptDetached(Uint8List m, Uint8List ad,
          Uint8List nsec, Uint8List npub, Uint8List k,
          {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(nsec == null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        'k',
        'Invalid length');

    final Map result = await _channel.invokeMethod(
        'crypto_aead_chacha20poly1305_ietf_encrypt_detached', {
      'm': m,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return result.cast<String, Uint8List>();
  }

  /// Verifies and decrypts a cipher text and mac produced by encrypt detached.
  static Future<Uint8List> cryptoAeadChacha20poly1305IetfDecryptDetached(
      Uint8List nsec,
      Uint8List c,
      Uint8List mac,
      Uint8List ad,
      Uint8List npub,
      Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(nsec == null);
    assert(c != null);
    assert(mac != null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        mac.length,
        crypto_aead_chacha20poly1305_ietf_ABYTES,
        crypto_aead_chacha20poly1305_ietf_ABYTES,
        'mac',
        'Invalid length');
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        'k',
        'Invalid length');

    final Uint8List m = await _channel
        .invokeMethod('crypto_aead_chacha20poly1305_ietf_decrypt_detached', {
      'c': c,
      'mac': mac,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return m;
  }

  /// Generates a random key.
  static Future<Uint8List> cryptoAeadChacha20poly1305IetfKeygen(
      {bool useBackgroundThread = false}) async {
    final Uint8List k = await _channel.invokeMethod(
        'crypto_aead_chacha20poly1305_ietf_keygen',
        {'bgThread': useBackgroundThread});
    return k;
  }

  //
  // crypto_aead_xchacha20poly1305_ietf
  //
  /// Encrypts a message with optional additional data, a key and a nonce.
  static Future<Uint8List> cryptoAeadXchacha20poly1305IetfEncrypt(
      Uint8List m, Uint8List ad, Uint8List nsec, Uint8List npub, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(nsec == null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        'k',
        'Invalid length');

    final Uint8List c = await _channel.invokeMethod(
        'crypto_aead_xchacha20poly1305_ietf_encrypt', {
      'm': m,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return c;
  }

  /// Verifies and decrypts a cipher text produced by encrypt.
  static Future<Uint8List> cryptoAeadXchacha20poly1305IetfDecrypt(
      Uint8List nsec, Uint8List c, Uint8List ad, Uint8List npub, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(nsec == null);
    assert(c != null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        'k',
        'Invalid length');

    final Uint8List m = await _channel.invokeMethod(
        'crypto_aead_xchacha20poly1305_ietf_decrypt', {
      'c': c,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return m;
  }

  /// Encrypts a message with optional additional data, a key and a nonce. Returns a ciphertext and mac.
  static Future<Map<String, Uint8List>>
      cryptoAeadXchacha20poly1305IetfEncryptDetached(Uint8List m, Uint8List ad,
          Uint8List nsec, Uint8List npub, Uint8List k,
          {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(nsec == null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        'k',
        'Invalid length');

    final Map result = await _channel.invokeMethod(
        'crypto_aead_xchacha20poly1305_ietf_encrypt_detached', {
      'm': m,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return result.cast<String, Uint8List>();
  }

  /// Verifies and decrypts a cipher text and mac produced by encrypt detached.
  static Future<Uint8List> cryptoAeadXchacha20poly1305IetfDecryptDetached(
      Uint8List nsec,
      Uint8List c,
      Uint8List mac,
      Uint8List ad,
      Uint8List npub,
      Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(nsec == null);
    assert(c != null);
    assert(mac != null);
    assert(npub != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        mac.length,
        crypto_aead_xchacha20poly1305_ietf_ABYTES,
        crypto_aead_xchacha20poly1305_ietf_ABYTES,
        'mac',
        'Invalid length');
    RangeError.checkValueInInterval(
        npub.length,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        'npub',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        'k',
        'Invalid length');

    final Uint8List m = await _channel
        .invokeMethod('crypto_aead_xchacha20poly1305_ietf_decrypt_detached', {
      'c': c,
      'mac': mac,
      'ad': ad,
      'npub': npub,
      'k': k,
      'bgThread': useBackgroundThread
    });
    return m;
  }

  /// Generates a random key.
  static Future<Uint8List> cryptoAeadXchacha20poly1305IetfKeygen(
      {bool useBackgroundThread = false}) async {
    final Uint8List k = await _channel.invokeMethod(
        'crypto_aead_xchacha20poly1305_ietf_keygen',
        {'bgThread': useBackgroundThread});
    return k;
  }

  //
  // crypto_auth
  //
  /// Computes a tag for specified input and key.
  static Future<Uint8List> cryptoAuth(Uint8List i, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(k.length, crypto_auth_KEYBYTES,
        crypto_auth_KEYBYTES, 'k', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_auth', {'in': i, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Verifies that the tag stored at h is a valid tag for the input and key.
  static Future<bool> cryptoAuthVerify(Uint8List h, Uint8List i, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(h != null);
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(
        h.length, crypto_auth_BYTES, crypto_auth_BYTES, 'h', 'Invalid length');
    RangeError.checkValueInInterval(k.length, crypto_auth_KEYBYTES,
        crypto_auth_KEYBYTES, 'k', 'Invalid length');

    final bool result = await _channel.invokeMethod('crypto_auth_verify',
        {'h': h, 'in': i, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Generates a random key.
  static Future<Uint8List> cryptoAuthKeygen(
      {bool useBackgroundThread = false}) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_auth_keygen', {'bgThread': useBackgroundThread});
    return result;
  }

  //
  // crypto_box
  //
  /// Deterministically derive a key pair from a single key seed.
  static Future<Map<String, Uint8List>> cryptoBoxSeedKeypair(Uint8List seed,
      {bool useBackgroundThread = false}) async {
    assert(seed != null);
    RangeError.checkValueInInterval(seed.length, crypto_box_SEEDBYTES,
        crypto_box_SEEDBYTES, 'seed', 'Invalid length');

    final Map result = await _channel.invokeMethod('crypto_box_seed_keypair',
        {'seed': seed, 'bgThread': useBackgroundThread});
    return result.cast<String, Uint8List>();
  }

  /// Generates a random secret key and a corresponding public key.
  static Future<Map<String, Uint8List>> cryptoBoxKeypair(
      {bool useBackgroundThread = false}) async {
    final Map result = await _channel
        .invokeMethod('crypto_box_keypair', {'bgThread': useBackgroundThread});
    return result.cast<String, Uint8List>();
  }

  /// Encrypts a message with a recipient's public key, a sender's secret key and a nonce.
  static Future<Uint8List> cryptoBoxEasy(
      Uint8List m, Uint8List n, Uint8List pk, Uint8List sk,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(n != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(n.length, crypto_box_NONCEBYTES,
        crypto_box_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, crypto_box_PUBLICKEYBYTES,
        crypto_box_PUBLICKEYBYTES, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, crypto_box_SECRETKEYBYTES,
        crypto_box_SECRETKEYBYTES, 'sk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod('crypto_box_easy',
        {'m': m, 'n': n, 'pk': pk, 'sk': sk, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Verifies and decrypts a ciphertext produced by [cryptoBoxEasy].
  static Future<Uint8List> cryptoBoxOpenEasy(
      Uint8List c, Uint8List n, Uint8List pk, Uint8List sk,
      {bool useBackgroundThread = false}) async {
    assert(c != null);
    assert(n != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(n.length, crypto_box_NONCEBYTES,
        crypto_box_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, crypto_box_PUBLICKEYBYTES,
        crypto_box_PUBLICKEYBYTES, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, crypto_box_SECRETKEYBYTES,
        crypto_box_SECRETKEYBYTES, 'sk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod('crypto_box_open_easy',
        {'c': c, 'n': n, 'pk': pk, 'sk': sk, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Encrypts a message with a recipient's public key, a sender's secret key and a nonce. Returns the encrypted message and mac.
  static Future<Map<String, Uint8List>> cryptoBoxDetached(
      Uint8List m, Uint8List n, Uint8List pk, Uint8List sk,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(n != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(n.length, crypto_box_NONCEBYTES,
        crypto_box_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, crypto_box_PUBLICKEYBYTES,
        crypto_box_PUBLICKEYBYTES, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, crypto_box_SECRETKEYBYTES,
        crypto_box_SECRETKEYBYTES, 'sk', 'Invalid length');

    final Map result = await _channel.invokeMethod('crypto_box_detached',
        {'m': m, 'n': n, 'pk': pk, 'sk': sk, 'bgThread': useBackgroundThread});
    return result.cast<String, Uint8List>();
  }

  /// Verifies and decrypts a ciphertext produced by [cryptoBoxDetached].
  static Future<Uint8List> cryptoBoxOpenDetached(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List pk, Uint8List sk,
      {bool useBackgroundThread = false}) async {
    assert(c != null);
    assert(mac != null);
    assert(n != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(mac.length, crypto_box_MACBYTES,
        crypto_box_MACBYTES, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(n.length, crypto_box_NONCEBYTES,
        crypto_box_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, crypto_box_PUBLICKEYBYTES,
        crypto_box_PUBLICKEYBYTES, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, crypto_box_SECRETKEYBYTES,
        crypto_box_SECRETKEYBYTES, 'sk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_box_open_detached', {
      'c': c,
      'mac': mac,
      'n': n,
      'pk': pk,
      'sk': sk,
      'bgThread': useBackgroundThread
    });
    return result;
  }

  /// Computes a shared secret key given a public key and a secret key.
  static Future<Uint8List> cryptoBoxBeforenm(Uint8List pk, Uint8List sk,
      {bool useBackgroundThread = false}) async {
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(pk.length, crypto_box_PUBLICKEYBYTES,
        crypto_box_PUBLICKEYBYTES, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, crypto_box_SECRETKEYBYTES,
        crypto_box_SECRETKEYBYTES, 'sk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod('crypto_box_beforenm',
        {'pk': pk, 'sk': sk, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Encrypts a message with a shared secret key and a nonce.
  static Future<Uint8List> cryptoBoxEasyAfternm(
      Uint8List m, Uint8List n, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, crypto_box_NONCEBYTES,
        crypto_box_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, crypto_box_BEFORENMBYTES,
        crypto_box_BEFORENMBYTES, 'k', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_box_easy_afternm',
        {'m': m, 'n': n, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Verifies and decrypts a ciphertext with a shared secret key and a nonce.
  static Future<Uint8List> cryptoBoxOpenEasyAfternm(
      Uint8List c, Uint8List n, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(c != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, crypto_box_NONCEBYTES,
        crypto_box_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, crypto_box_BEFORENMBYTES,
        crypto_box_BEFORENMBYTES, 'k', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_box_open_easy_afternm',
        {'c': c, 'n': n, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Encrypts a message with a shared secret key and a nonce. Returns the encrypted message and mac.
  static Future<Map<String, Uint8List>> cryptoBoxDetachedAfternm(
      Uint8List m, Uint8List n, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, crypto_box_NONCEBYTES,
        crypto_box_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, crypto_box_BEFORENMBYTES,
        crypto_box_BEFORENMBYTES, 'k', 'Invalid length');

    final Map result = await _channel.invokeMethod(
        'crypto_box_detached_afternm',
        {'m': m, 'n': n, 'k': k, 'bgThread': useBackgroundThread});
    return result.cast<String, Uint8List>();
  }

  /// Verifies and decrypts a ciphertext with a mac, a shared secret key and a nonce.
  static Future<Uint8List> cryptoBoxOpenDetachedAfternm(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(c != null);
    assert(mac != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(mac.length, crypto_box_MACBYTES,
        crypto_box_MACBYTES, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(n.length, crypto_box_NONCEBYTES,
        crypto_box_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, crypto_box_BEFORENMBYTES,
        crypto_box_BEFORENMBYTES, 'k', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_box_open_detached_afternm',
        {'c': c, 'mac': mac, 'n': n, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  //
  // crypto_box_seal
  //
  /// Encrypts a message for a recipient whose public key is pk
  static Future<Uint8List> cryptoBoxSeal(Uint8List m, Uint8List pk,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(pk != null);
    RangeError.checkValueInInterval(pk.length, crypto_box_PUBLICKEYBYTES,
        crypto_box_PUBLICKEYBYTES, 'pk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_box_seal', {'m': m, 'pk': pk, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Decrypts the ciphertext using specified key pair.
  static Future<Uint8List> cryptoBoxSealOpen(
      Uint8List c, Uint8List pk, Uint8List sk,
      {bool useBackgroundThread = false}) async {
    assert(c != null);
    assert(pk != null);
    assert(sk != null);
    RangeError.checkValueInInterval(pk.length, crypto_box_PUBLICKEYBYTES,
        crypto_box_PUBLICKEYBYTES, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, crypto_box_SECRETKEYBYTES,
        crypto_box_SECRETKEYBYTES, 'sk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod('crypto_box_seal_open',
        {'c': c, 'pk': pk, 'sk': sk, 'bgThread': useBackgroundThread});
    return result;
  }

  //
  // crypto_generichash
  //
  /// Computes a fingerprint of specified length for given input and key.
  static Future<Uint8List> cryptoGenerichash(
      int outlen, Uint8List i, Uint8List key,
      {bool useBackgroundThread = false}) async {
    assert(outlen != null);
    assert(i != null);
    RangeError.checkValueInInterval(
        outlen, crypto_generichash_BYTES_MIN, crypto_generichash_BYTES_MAX);
    if (key != null) {
      RangeError.checkValueInInterval(
          key.length,
          crypto_generichash_KEYBYTES_MIN,
          crypto_generichash_KEYBYTES_MAX,
          'key',
          'Invalid length');
    }

    final Uint8List result = await _channel.invokeMethod('crypto_generichash', {
      'outlen': outlen,
      'in': i,
      'key': key,
      'bgThread': useBackgroundThread
    });
    return result;
  }

  /// Initializes the hash state for the streaming API.
  static Future<Uint8List> cryptoGenerichashInit(Uint8List key, int outlen,
      {bool useBackgroundThread = false}) async {
    assert(outlen != null);
    if (key != null) {
      RangeError.checkValueInInterval(
          key.length,
          crypto_generichash_KEYBYTES_MIN,
          crypto_generichash_KEYBYTES_MAX,
          'key',
          'Invalid length');
    }
    RangeError.checkValueInInterval(
        outlen, crypto_generichash_BYTES_MIN, crypto_generichash_BYTES_MAX);

    final Uint8List result = await _channel.invokeMethod(
        'crypto_generichash_init',
        {'key': key, 'outlen': outlen, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Computes the hash for a part of a message.
  static Future<Uint8List> cryptoGenerichashUpdate(Uint8List state, Uint8List i,
      {bool useBackgroundThread = false}) async {
    assert(state != null);
    assert(i != null);

    final Uint8List result = await _channel.invokeMethod(
        'crypto_generichash_update',
        {'state': state, 'in': i, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Completes the hash computation and returns the hash.
  static Future<Uint8List> cryptoGenerichashFinal(Uint8List state, int outlen,
      {bool useBackgroundThread = false}) async {
    assert(state != null);
    assert(outlen != null);
    RangeError.checkValueInInterval(
        outlen, crypto_generichash_BYTES_MIN, crypto_generichash_BYTES_MAX);

    final Uint8List result = await _channel.invokeMethod(
        'crypto_generichash_final',
        {'state': state, 'outlen': outlen, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Generates a random key for generic hashing.
  static Future<Uint8List> cryptoGenerichashKeygen(
      {bool useBackgroundThread = false}) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_generichash_keygen', {'bgThread': useBackgroundThread});
    return result;
  }

  //
  // crypto_kdf
  //
  /// Creates a master key.
  static Future<Uint8List> cryptoKdfKeygen(
      {bool useBackgroundThread = false}) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_kdf_keygen', {'bgThread': useBackgroundThread});
    return result;
  }

  /// Derives a subkey using a master key and a context.
  static Future<Uint8List> cryptoKdfDeriveFromKey(
      int subkeyLen, int subkeyId, Uint8List ctx, Uint8List key,
      {bool useBackgroundThread = false}) async {
    assert(subkeyLen != null);
    assert(subkeyId != null);
    assert(ctx != null);
    assert(key != null);
    RangeError.checkValueInInterval(ctx.length, crypto_kdf_CONTEXTBYTES,
        crypto_kdf_CONTEXTBYTES, 'ctx', 'Invalid length');
    RangeError.checkValueInInterval(key.length, crypto_kdf_KEYBYTES,
        crypto_kdf_KEYBYTES, 'key', 'Invalid length');

    final Uint8List result =
        await _channel.invokeMethod('crypto_kdf_derive_from_key', {
      'subkey_len': subkeyLen,
      'subkey_id': subkeyId,
      'ctx': ctx,
      'key': key,
      'bgThread': useBackgroundThread
    });
    return result;
  }

  //
  // crypto_kx
  //
  /// Creates a new key pair.
  static Future<Map<String, Uint8List>> cryptoKxKeypair(
      {bool useBackgroundThread = false}) async {
    final Map result = await _channel
        .invokeMethod('crypto_kx_keypair', {'bgThread': useBackgroundThread});
    return result.cast<String, Uint8List>();
  }

  /// Computes a deterministic key pair from the seed.
  static Future<Map<String, Uint8List>> cryptoKxSeedKeypair(Uint8List seed,
      {bool useBackgroundThread = false}) async {
    assert(seed != null);
    RangeError.checkValueInInterval(seed.length, crypto_kx_SEEDBYTES,
        crypto_kx_SEEDBYTES, 'seed', 'Invalid length');

    final Map result = await _channel.invokeMethod('crypto_kx_seed_keypair',
        {'seed': seed, 'bgThread': useBackgroundThread});
    return result.cast<String, Uint8List>();
  }

  /// Computes a pair of shared keys (rx and tx) using the client's public key, the client's secret key and the server's public key.
  static Future<Map<String, Uint8List>> cryptoKxClientSessionKeys(
      Uint8List clientPk, Uint8List clientSk, Uint8List serverPk,
      {bool useBackgroundThread = false}) async {
    assert(clientPk != null);
    assert(clientSk != null);
    assert(serverPk != null);
    RangeError.checkValueInInterval(clientPk.length, crypto_kx_PUBLICKEYBYTES,
        crypto_kx_PUBLICKEYBYTES, 'clientPk', 'Invalid length');
    RangeError.checkValueInInterval(clientSk.length, crypto_kx_SECRETKEYBYTES,
        crypto_kx_SECRETKEYBYTES, 'clientSk', 'Invalid length');
    RangeError.checkValueInInterval(serverPk.length, crypto_kx_PUBLICKEYBYTES,
        crypto_kx_PUBLICKEYBYTES, 'serverPk', 'Invalid length');

    final Map result =
        await _channel.invokeMethod('crypto_kx_client_session_keys', {
      'client_pk': clientPk,
      'client_sk': clientSk,
      'server_pk': serverPk,
      'bgThread': useBackgroundThread
    });
    return result.cast<String, Uint8List>();
  }

  /// Computes a pair of shared keys (rx and tx) using the server's public key, the server's secret key and the client's public key.
  static Future<Map<String, Uint8List>> cryptoKxServerSessionKeys(
      Uint8List serverPk, Uint8List serverSk, Uint8List clientPk,
      {bool useBackgroundThread = false}) async {
    assert(serverPk != null);
    assert(serverSk != null);
    assert(clientPk != null);
    RangeError.checkValueInInterval(serverPk.length, crypto_kx_PUBLICKEYBYTES,
        crypto_kx_PUBLICKEYBYTES, 'serverPk', 'Invalid length');
    RangeError.checkValueInInterval(serverSk.length, crypto_kx_SECRETKEYBYTES,
        crypto_kx_SECRETKEYBYTES, 'serverSk', 'Invalid length');
    RangeError.checkValueInInterval(clientPk.length, crypto_kx_PUBLICKEYBYTES,
        crypto_kx_PUBLICKEYBYTES, 'clientPk', 'Invalid length');

    final Map result =
        await _channel.invokeMethod('crypto_kx_server_session_keys', {
      'server_pk': serverPk,
      'server_sk': serverSk,
      'client_pk': clientPk,
      'bgThread': useBackgroundThread
    });
    return result.cast<String, Uint8List>();
  }

  //
  // crypto_onetimeauth
  //
  /// Authenticates a message using a secret key.
  static Future<Uint8List> cryptoOnetimeauth(Uint8List i, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(k.length, crypto_onetimeauth_KEYBYTES,
        crypto_onetimeauth_KEYBYTES, 'k', 'Invalid length');
    final Uint8List result = await _channel.invokeMethod('crypto_onetimeauth',
        {'in': i, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Verifies that h is a correct authenticator for the message using given secret key.
  static Future<bool> cryptoOnetimeauthVerify(
      Uint8List h, Uint8List i, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(h != null);
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(h.length, crypto_onetimeauth_BYTES,
        crypto_onetimeauth_BYTES, 'h', 'Invalid length');
    RangeError.checkValueInInterval(k.length, crypto_onetimeauth_KEYBYTES,
        crypto_onetimeauth_KEYBYTES, 'k', 'Invalid length');

    final bool result = await _channel.invokeMethod('crypto_onetimeauth_verify',
        {'h': h, 'in': i, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Initializes the authentication state for the streaming API.
  static Future<Uint8List> cryptoOnetimeauthInit(Uint8List key,
      {bool useBackgroundThread = false}) async {
    assert(key != null);
    RangeError.checkValueInInterval(key.length, crypto_onetimeauth_KEYBYTES,
        crypto_onetimeauth_KEYBYTES, 'key', 'Invalid length');
    final Uint8List result = await _channel.invokeMethod(
        'crypto_onetimeauth_init',
        {'key': key, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Computes the authenticator from sequential chunks of the message.
  static Future<Uint8List> cryptoOnetimeauthUpdate(Uint8List state, Uint8List i,
      {bool useBackgroundThread = false}) async {
    assert(state != null);
    assert(i != null);
    final Uint8List result = await _channel.invokeMethod(
        'crypto_onetimeauth_update',
        {'state': state, 'in': i, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Completes the computation and returns the authenticator.
  static Future<Uint8List> cryptoOnetimeauthFinal(Uint8List state,
      {bool useBackgroundThread = false}) async {
    assert(state != null);
    final Uint8List result = await _channel.invokeMethod(
        'crypto_onetimeauth_final',
        {'state': state, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Generates a random key for use in onetime authentication.
  static Future<Uint8List> cryptoOnetimeauthKeygen(
      {bool useBackgroundThread = false}) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_onetimeauth_keygen', {'bgThread': useBackgroundThread});
    return result;
  }

  //
  // crypto_pwhash
  //
  /// Derives a key from a password and a salt.
  static Future<Uint8List> cryptoPwhash(int outlen, Uint8List passwd,
      Uint8List salt, int opslimit, int memlimit, int alg,
      {bool useBackgroundThread = true}) async {
    assert(outlen != null);
    assert(passwd != null);
    assert(salt != null);
    assert(opslimit != null);
    assert(memlimit != null);
    assert(alg != null);
    RangeError.checkValueInInterval(
        outlen, crypto_pwhash_BYTES_MIN, crypto_pwhash_BYTES_MAX, 'outlen');
    RangeError.checkValueInInterval(passwd.length, crypto_pwhash_PASSWD_MIN,
        crypto_pwhash_PASSWD_MAX, 'passwd', 'Invalid length');
    RangeError.checkValueInInterval(salt.length, crypto_pwhash_SALTBYTES,
        crypto_pwhash_SALTBYTES, 'salt', 'Invalid length');
    RangeError.checkValueInInterval(opslimit, crypto_pwhash_OPSLIMIT_MIN,
        crypto_pwhash_OPSLIMIT_MAX, 'opslimit');
    RangeError.checkValueInInterval(memlimit, crypto_pwhash_MEMLIMIT_MIN,
        crypto_pwhash_MEMLIMIT_MAX, 'memlimit');
    RangeError.checkValueInInterval(alg, crypto_pwhash_argon2i_ALG_ARGON2I13,
        crypto_pwhash_argon2id_ALG_ARGON2ID13, 'alg');
    final Uint8List result = await _channel.invokeMethod('crypto_pwhash', {
      'outlen': outlen,
      'passwd': passwd,
      'salt': salt,
      'opslimit': opslimit,
      'memlimit': memlimit,
      'alg': alg,
      'bgThread': useBackgroundThread
    });
    return result;
  }

  /// Derives an ASCII encoded string containing a hash, automatically generated salt, and other parameters required to verify the password.
  static Future<Uint8List> cryptoPwhashStr(
      Uint8List passwd, int opslimit, int memlimit,
      {bool useBackgroundThread = true}) async {
    assert(passwd != null);
    assert(opslimit != null);
    assert(memlimit != null);
    RangeError.checkValueInInterval(passwd.length, crypto_pwhash_PASSWD_MIN,
        crypto_pwhash_PASSWD_MAX, 'passwd', 'Invalid length');
    RangeError.checkValueInInterval(opslimit, crypto_pwhash_OPSLIMIT_MIN,
        crypto_pwhash_OPSLIMIT_MAX, 'opslimit');
    RangeError.checkValueInInterval(memlimit, crypto_pwhash_MEMLIMIT_MIN,
        crypto_pwhash_MEMLIMIT_MAX, 'memlimit');
    final Uint8List result = await _channel.invokeMethod('crypto_pwhash_str', {
      'passwd': passwd,
      'opslimit': opslimit,
      'memlimit': memlimit,
      'bgThread': useBackgroundThread
    });
    return result;
  }

  /// Verifies that str is a valid password verification string.
  static Future<bool> cryptoPwhashStrVerify(Uint8List str, Uint8List passwd,
      {bool useBackgroundThread = true}) async {
    assert(str != null);
    assert(passwd != null);
    RangeError.checkValueInInterval(passwd.length, crypto_pwhash_PASSWD_MIN,
        crypto_pwhash_PASSWD_MAX, 'passwd', 'Invalid length');
    final bool result = await _channel.invokeMethod('crypto_pwhash_str_verify',
        {'str': str, 'passwd': passwd, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Check if a password verification string matches the parameters opslimit and memlimit, and the current default algorithm.
  static Future<bool> cryptoPwhashStrNeedsRehash(
      Uint8List str, int opslimit, int memlimit,
      {bool useBackgroundThread = false}) async {
    assert(str != null);
    assert(opslimit != null);
    assert(memlimit != null);
    RangeError.checkValueInInterval(opslimit, crypto_pwhash_OPSLIMIT_MIN,
        crypto_pwhash_OPSLIMIT_MAX, 'opslimit');
    RangeError.checkValueInInterval(memlimit, crypto_pwhash_MEMLIMIT_MIN,
        crypto_pwhash_MEMLIMIT_MAX, 'memlimit');
    final bool result =
        await _channel.invokeMethod('crypto_pwhash_str_needs_rehash', {
      'str': str,
      'opslimit': opslimit,
      'memlimit': memlimit,
      'bgThread': useBackgroundThread
    });
    return result;
  }

  //
  // crypto_secretbox
  //
  /// Encrypts a message with a key and a nonce.
  static Future<Uint8List> cryptoSecretboxEasy(
      Uint8List m, Uint8List n, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, crypto_secretbox_NONCEBYTES,
        crypto_secretbox_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, crypto_secretbox_KEYBYTES,
        crypto_secretbox_KEYBYTES, 'k', 'Invalid length');
    final Uint8List result = await _channel.invokeMethod(
        'crypto_secretbox_easy',
        {'m': m, 'n': n, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Verifies and decrypts a ciphertext produced by [cryptoSecretboxEasy].
  static Future<Uint8List> cryptoSecretboxOpenEasy(
      Uint8List c, Uint8List n, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(c != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, crypto_secretbox_NONCEBYTES,
        crypto_secretbox_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, crypto_secretbox_KEYBYTES,
        crypto_secretbox_KEYBYTES, 'k', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_secretbox_open_easy',
        {'c': c, 'n': n, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Encrypts a message with a key and a nonce, and returns the encrypted message and mac.
  static Future<Map<String, Uint8List>> cryptoSecretboxDetached(
      Uint8List m, Uint8List n, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(n.length, crypto_secretbox_NONCEBYTES,
        crypto_secretbox_NONCEBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, crypto_secretbox_KEYBYTES,
        crypto_secretbox_KEYBYTES, 'k', 'Invalid length');

    final Map result = await _channel.invokeMethod('crypto_secretbox_detached',
        {'m': m, 'n': n, 'k': k, 'bgThread': useBackgroundThread});
    return result.cast<String, Uint8List>();
  }

  /// Verifies and decrypts an encrypted message.
  static Future<Uint8List> cryptoSecretboxOpenDetached(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(c != null);
    assert(mac != null);
    assert(n != null);
    assert(k != null);
    RangeError.checkValueInInterval(mac.length, crypto_secretbox_MACBYTES,
        crypto_secretbox_MACBYTES, 'mac');
    RangeError.checkValueInInterval(n.length, crypto_secretbox_NONCEBYTES,
        crypto_secretbox_NONCEBYTES, 'n');
    RangeError.checkValueInInterval(
        k.length, crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES, 'k');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_secretbox_open_detached',
        {'c': c, 'mac': mac, 'n': n, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Creates a random key
  static Future<Uint8List> cryptoSecretboxKeygen(
      {bool useBackgroundThread = false}) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_secretbox_keygen', {'bgThread': useBackgroundThread});
    return result;
  }

  //
  // crypto_scalarmult
  //
  /// Computes a public key given specified secret key.
  static Future<Uint8List> cryptoScalarmultBase(Uint8List n,
      {bool useBackgroundThread = false}) async {
    assert(n != null);
    RangeError.checkValueInInterval(n.length, crypto_scalarmult_SCALARBYTES,
        crypto_scalarmult_SCALARBYTES, 'n', 'Invalid length');
    final Uint8List result = await _channel.invokeMethod(
        'crypto_scalarmult_base', {'n': n, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Computes a shared secret given a user's secret key and another user's public key.
  static Future<Uint8List> cryptoScalarmult(Uint8List n, Uint8List p,
      {bool useBackgroundThread = false}) async {
    assert(n != null);
    assert(p != null);
    RangeError.checkValueInInterval(n.length, crypto_scalarmult_SCALARBYTES,
        crypto_scalarmult_SCALARBYTES, 'n', 'Invalid length');
    RangeError.checkValueInInterval(p.length, crypto_scalarmult_BYTES,
        crypto_scalarmult_BYTES, 'p', 'Invalid length');
    final Uint8List result = await _channel.invokeMethod(
        'crypto_scalarmult', {'n': n, 'p': p, 'bgThread': useBackgroundThread});
    return result;
  }

  //
  // crypto_shorthash
  //
  /// Computes a fixed-size fingerprint for specified input and key.
  static Future<Uint8List> cryptoShorthash(Uint8List i, Uint8List k,
      {bool useBackgroundThread = false}) async {
    assert(i != null);
    assert(k != null);
    RangeError.checkValueInInterval(k.length, crypto_shorthash_KEYBYTES,
        crypto_shorthash_KEYBYTES, 'k', 'Invalid length');
    final Uint8List result = await _channel.invokeMethod(
        'crypto_shorthash', {'in': i, 'k': k, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Generates a random key.
  static Future<Uint8List> cryptoShorthashKeygen(
      {bool useBackgroundThread = false}) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_shorthash_keygen', {'bgThread': useBackgroundThread});
    return result;
  }

  //
  // crypto_sign
  //
  /// Deterministically derives a key pair from a single seed.
  static Future<Map<String, Uint8List>> cryptoSignSeedKeypair(Uint8List seed,
      {bool useBackgroundThread = false}) async {
    assert(seed != null);
    RangeError.checkValueInInterval(seed.length, crypto_sign_SEEDBYTES,
        crypto_sign_SEEDBYTES, 'seed', 'Invalid length');

    final Map result = await _channel.invokeMethod('crypto_sign_seed_keypair',
        {'seed': seed, 'bgThread': useBackgroundThread});
    return result.cast<String, Uint8List>();
  }

  /// Randomly generates a secret key and a corresponding public key.
  static Future<Map<String, Uint8List>> cryptoSignKeypair(
      {bool useBackgroundThread = false}) async {
    final Map result = await _channel
        .invokeMethod('crypto_sign_keypair', {'bgThread': useBackgroundThread});
    return result.cast<String, Uint8List>();
  }

  /// Prepends a signature to a message using specified secret key.
  static Future<Uint8List> cryptoSign(Uint8List m, Uint8List sk,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(sk != null);
    RangeError.checkValueInInterval(sk.length, crypto_sign_SECRETKEYBYTES,
        crypto_sign_SECRETKEYBYTES, 'sk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_sign', {'m': m, 'sk': sk, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Checks that the signed message has a valid signature for specified public key.
  static Future<Uint8List> cryptoSignOpen(Uint8List sm, Uint8List pk,
      {bool useBackgroundThread = false}) async {
    assert(sm != null);
    assert(pk != null);
    RangeError.checkValueInInterval(pk.length, crypto_sign_PUBLICKEYBYTES,
        crypto_sign_PUBLICKEYBYTES, 'pk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod('crypto_sign_open',
        {'sm': sm, 'pk': pk, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Computes a signature for given message.
  static Future<Uint8List> cryptoSignDetached(Uint8List m, Uint8List sk,
      {bool useBackgroundThread = false}) async {
    assert(m != null);
    assert(sk != null);
    RangeError.checkValueInInterval(sk.length, crypto_sign_SECRETKEYBYTES,
        crypto_sign_SECRETKEYBYTES, 'sk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod('crypto_sign_detached',
        {'m': m, 'sk': sk, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Verifies that the signature is valid for given message and signer's public key.
  static Future<bool> cryptoSignVerifyDetached(
      Uint8List sig, Uint8List m, Uint8List pk,
      {bool useBackgroundThread = false}) async {
    assert(sig != null);
    assert(m != null);
    assert(pk != null);
    RangeError.checkValueInInterval(sig.length, crypto_sign_BYTES,
        crypto_sign_BYTES, 'sig', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, crypto_sign_PUBLICKEYBYTES,
        crypto_sign_PUBLICKEYBYTES, 'pk', 'Invalid length');

    final bool result = await _channel.invokeMethod(
        'crypto_sign_verify_detached',
        {'sig': sig, 'm': m, 'pk': pk, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Initializes the sign state for the streaming API.
  static Future<Uint8List> cryptoSignInit(
      {bool useBackgroundThread = false}) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_sign_init', {'bgThread': useBackgroundThread});
    return result;
  }

  /// Adds a new chunk to the message that will eventually be signed.
  static Future<Uint8List> cryptoSignUpdate(Uint8List state, Uint8List m,
      {bool useBackgroundThread = false}) async {
    assert(state != null);
    assert(m != null);

    final Uint8List result = await _channel.invokeMethod('crypto_sign_update',
        {'state': state, 'm': m, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Computes a signature for the previously supplied message, using the secret key.
  static Future<Uint8List> cryptoSignFinalCreate(Uint8List state, Uint8List sk,
      {bool useBackgroundThread = false}) async {
    assert(state != null);
    assert(sk != null);
    RangeError.checkValueInInterval(sk.length, crypto_sign_SECRETKEYBYTES,
        crypto_sign_SECRETKEYBYTES, 'sk', 'Invalid length');

    final Uint8List result = await _channel.invokeMethod(
        'crypto_sign_final_create',
        {'state': state, 'sk': sk, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Verifies whether the signature is valid for the message whose content has been previously supplied, using specified public key.
  static Future<bool> cryptoSignFinalVerify(
      Uint8List state, Uint8List sig, Uint8List pk,
      {bool useBackgroundThread = false}) async {
    assert(state != null);
    assert(sig != null);
    assert(pk != null);
    RangeError.checkValueInInterval(sig.length, crypto_sign_BYTES,
        crypto_sign_BYTES, 'sig', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, crypto_sign_PUBLICKEYBYTES,
        crypto_sign_PUBLICKEYBYTES, 'pk', 'Invalid length');

    final bool result = await _channel.invokeMethod(
        'crypto_sign_final_verify', {
      'state': state,
      'sig': sig,
      'pk': pk,
      'bgThread': useBackgroundThread
    });
    return result;
  }

  //
  // randombytes
  //
  /// Returns an unpredictable sequence of bytes of size [size].
  static Future<Uint8List> randombytesBuf(int size,
      {bool useBackgroundThread = false}) async {
    assert(size != null);
    RangeError.checkNotNegative(size);
    final Uint8List result = await _channel.invokeMethod(
        'randombytes_buf', {'size': size, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Returns an unpredictable sequence of bytes of size [size] using given [seed].
  ///
  /// For a given seed, this function will always output the same sequence
  static Future<Uint8List> randombytesBufDeterministic(int size, Uint8List seed,
      {bool useBackgroundThread = false}) async {
    assert(size != null);
    assert(seed != null);
    RangeError.checkNotNegative(size);
    RangeError.checkValueInInterval(seed.length, randombytes_SEEDBYTES,
        randombytes_SEEDBYTES, 'seed', 'Invalid length');
    final Uint8List result = await _channel.invokeMethod(
        'randombytes_buf_deterministic',
        {'size': size, 'seed': seed, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Returns an unpredictable value between 0 and 0xffffffff (included).
  static Future<int> randombytesRandom(
      {bool useBackgroundThread = false}) async {
    final int result = await _channel
        .invokeMethod('randombytes_random', {'bgThread': useBackgroundThread});
    return result;
  }

  /// Returns an unpredictable value between 0 and upper_bound (excluded).
  ///
  /// It guarantees a uniform distribution of the possible output values even when [upperBound] is not a power of 2.
  static Future<int> randombytesUniform(int upperBound,
      {bool useBackgroundThread = false}) async {
    assert(upperBound != null);
    RangeError.checkNotNegative(upperBound);
    final int result = await _channel.invokeMethod('randombytes_uniform',
        {'upper_bound': upperBound, 'bgThread': useBackgroundThread});
    return result;
  }

  /// Reseeds the pseudo-random number generator.
  static Future<int> randombytesStir({bool useBackgroundThread = false}) async {
    final int result = await _channel
        .invokeMethod('randombytes_stir', {'bgThread': useBackgroundThread});
    return result;
  }

  /// Deallocates the global resources used by the pseudo-random number generator.
  ///
  /// Explicitly calling this function is almost never required.
  static Future<int> randombytesClose(
      {bool useBackgroundThread = false}) async {
    final int result = await _channel
        .invokeMethod('randombytes_close', {'bgThread': useBackgroundThread});
    return result;
  }

  //
  // sodium_version
  //
  /// Retrieves the version of the loaded libsodium library (currently 1.0.16).
  static Future<String> sodiumVersionString(
      {bool useBackgroundThread = false}) async {
    final String result = await _channel.invokeMethod(
        'sodium_version_string', {'bgThread': useBackgroundThread});
    return result;
  }
}
