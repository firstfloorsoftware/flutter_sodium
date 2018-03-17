import 'dart:async';
import 'dart:typed_data';
import 'package:flutter/services.dart';
export 'src/constants.dart';

/// Sodium is a modern, easy-to-use software library for encryption, decryption, signatures, password hashing and more.
class Sodium {
  static const MethodChannel _channel = const MethodChannel('flutter_sodium');

  //
  // crypto_auth
  //
  /// Computes a tag for specified input and key.
  static Future<Uint8List> cryptoAuth(Uint8List i, Uint8List k) =>
      _channel.invokeMethod('crypto_auth', {'in': i, 'k': k});

  /// Verifies that the tag stored at h is a valid tag for the input and key.
  static Future<bool> cryptoAuthVerify(Uint8List h, Uint8List i, Uint8List k) =>
      _channel.invokeMethod('crypto_auth_verify', {'h': h, 'in': i, 'k': k});

  /// Generates a random key.
  static Future<Uint8List> cryptoAuthKeygen() =>
      _channel.invokeMethod('crypto_auth_keygen');

  //
  // crypto_box
  //
  /// Deterministically derive a key pair from a single key seed.
  static Future<Map<String, Uint8List>> cryptoBoxSeedKeypair(Uint8List seed) =>
      _channel.invokeMethod('crypto_box_seed_keypair', {'seed': seed});

  /// Generates a random secret key and a corresponding public key.
  static Future<Map<String, Uint8List>> cryptoBoxKeypair() =>
      _channel.invokeMethod('crypto_box_keypair');

  //
  // crypto_box_seal
  //
  /// Encrypts a message for a recipient whose public key is pk
  static Future<Uint8List> cryptoBoxSeal(Uint8List m, Uint8List pk) =>
      _channel.invokeMethod('crypto_box_seal', {'m': m, 'pk': pk});

  /// Decrypts the ciphertext using specified key pair.
  static Future<Uint8List> cryptoBoxSealOpen(
          Uint8List c, Uint8List pk, Uint8List sk) =>
      _channel
          .invokeMethod('crypto_box_seal_open', {'c': c, 'pk': pk, 'sk': sk});

  //
  // crypto_generichash
  //
  /// Computes a fingerprint of specified length for given input and key.
  static Future<Uint8List> cryptoGenerichash(
          int outlen, Uint8List i, Uint8List key) =>
      _channel.invokeMethod(
          'crypto_generichash', {'outlen': outlen, 'in': i, 'key': key});

  /// Initializes the hash state for the streaming API.
  static Future<Uint8List> cryptoGenerichashInit(Uint8List key, int outlen) =>
      _channel.invokeMethod(
          'crypto_generichash_init', {'key': key, 'outlen': outlen});

  /// Computes the hash for a part of a message.
  static Future<Uint8List> cryptoGenerichashUpdate(
          Uint8List state, Uint8List i) =>
      _channel
          .invokeMethod('crypto_generichash_update', {'state': state, 'in': i});

  /// Completes the hash computation and returns the hash.
  static Future<Uint8List> cryptoGenerichashFinal(
          Uint8List state, int outlen) =>
      _channel.invokeMethod(
          'crypto_generichash_final', {'state': state, 'outlen': outlen});

  /// Generates a random key for generic hashing.
  static Future<Uint8List> cryptoGenerichashKeygen() =>
      _channel.invokeMethod('crypto_generichash_keygen');

  //
  // crypto_pwhash
  //
  /// Derives a key from a password and a salt.
  static Future<Uint8List> cryptoPwhash(int outlen, Uint8List passwd,
          Uint8List salt, int opslimit, int memlimit, int alg) =>
      _channel.invokeMethod('crypto_pwhash', {
        'outlen': outlen,
        'passwd': passwd,
        'salt': salt,
        'opslimit': opslimit,
        'memlimit': memlimit,
        'alg': alg
      });

  /// Derives an ASCII encoded string containing a hash, automatically generated salt, and other parameters required to verify the password.
  static Future<Uint8List> cryptoPwhashStr(
          Uint8List passwd, int opslimit, int memlimit) =>
      _channel.invokeMethod('crypto_pwhash_str', {
        'passwd': passwd,
        'opslimit': opslimit,
        'memlimit': memlimit,
      });

  /// Verifies that str is a valid password verification string.
  static Future<bool> cryptoPwhashStrVerify(Uint8List str, Uint8List passwd) =>
      _channel.invokeMethod(
          'crypto_pwhash_str_verify', {'str': str, 'passwd': passwd});

  /// Check if a password verification string matches the parameters opslimit and memlimit, and the current default algorithm.
  static Future<bool> cryptoPwhashStrNeedsRehash(
          Uint8List str, int opslimit, int memlimit) =>
      _channel.invokeMethod('crypto_pwhash_str_needs_rehash',
          {'str': str, 'opslimit': opslimit, 'memlimit': memlimit});

  //
  // crypto_shorthash
  //
  /// Computes a fixed-size fingerprint for specified input and key.
  static Future<Uint8List> cryptoShorthash(Uint8List i, Uint8List k) =>
      _channel.invokeMethod('crypto_shorthash', {'in': i, 'k': k});

  /// Generates a random key.
  static Future<Uint8List> cryptoShorthashKeygen() =>
      _channel.invokeMethod('crypto_shorthash_keygen');

  //
  // randombytes
  //
  /// Returns an unpredictable sequence of bytes of size [size].
  static Future<Uint8List> randombytesBuf(int size) =>
      _channel.invokeMethod('randombytes_buf', {'size': size});

  /// Returns an unpredictable sequence of bytes of size [size] using given [seed].
  ///
  /// For a given seed, this function will always output the same sequence
  static Future<Uint8List> randombytesBufDeterministic(
          int size, Uint8List seed) =>
      _channel.invokeMethod(
          'randombytes_buf_deterministic', {'size': size, 'seed': seed});

  /// Returns an unpredictable value between 0 and 0xffffffff (included).
  static Future<int> randombytesRandom() =>
      _channel.invokeMethod('randombytes_random');

  /// Returns an unpredictable value between 0 and upper_bound (excluded).
  ///
  /// It guarantees a uniform distribution of the possible output values even when [upperBound] is not a power of 2.
  static Future<int> randombytesUniform(int upperBound) =>
      _channel.invokeMethod('randombytes_uniform', {'upper_bound': upperBound});

  /// Reseeds the pseudo-random number generator.
  static Future<int> randombytesStir() =>
      _channel.invokeMethod('randombytes_stir');

  /// Deallocates the global resources used by the pseudo-random number generator.
  ///
  /// Explicitly calling this function is almost never required.
  static Future<int> randombytesClose() =>
      _channel.invokeMethod('randombytes_close');

  //
  // sodium_version
  //
  static Future<String> sodiumVersionString() =>
      _channel.invokeMethod('sodium_version_string');
}
