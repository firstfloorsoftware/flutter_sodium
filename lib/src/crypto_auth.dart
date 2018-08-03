import 'dart:async';
import 'dart:typed_data';
import 'dart:convert';
import '../flutter_sodium.dart';

/// Computes an authentication tag for a message and a secret key, and provides a way to verify that a given tag is valid for a given message and a key.
class CryptoAuth {
  /// Generates a random key for use with authentication.
  static Future<Uint8List> generateKey() => Sodium.cryptoAuthKeygen();

  /// Computes a tag for given string value and key.
  static Future<Uint8List> compute(String value, Uint8List key) =>
      Sodium.cryptoAuth(utf8.encode(value), key);

  /// Computes a tag for given value and key.
  static Future<Uint8List> computeBytes(Uint8List value, Uint8List key) =>
      Sodium.cryptoAuth(value, key);

  /// Verifies that the tag is valid for given string value and key.
  static Future<bool> verify(Uint8List tag, String value, Uint8List key) =>
      Sodium.cryptoAuthVerify(tag, utf8.encode(value), key);

  /// Verifies that the tag is valid for given value and key.
  static Future<bool> verifyBytes(
          Uint8List tag, Uint8List value, Uint8List key) =>
      Sodium.cryptoAuthVerify(tag, value, key);
}
