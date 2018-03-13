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
