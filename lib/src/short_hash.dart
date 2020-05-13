import 'dart:typed_data';
import 'dart:convert';
import 'sodium.dart';

/// Computes short hashes using the SipHash-2-4 algorithm.
class ShortHash {
  /// The primitive name.
  static String get primitive => Sodium.cryptoShorthashPrimitive;

  /// Generates a random key for use with short hashing.
  static Uint8List randomKey() => Sodium.cryptoShorthashKeygen();

  /// Computes a fixed-size fingerprint for given value and key.
  static Uint8List hash(Uint8List value, Uint8List key) =>
      Sodium.cryptoShorthash(value, key);

  /// Computes a fixed-size fingerprint for given string value and key.
  static Uint8List hashString(String value, Uint8List key) =>
      hash(utf8.encode(value), key);
}
