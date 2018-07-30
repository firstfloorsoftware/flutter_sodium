import 'dart:async';
import 'dart:typed_data';
import 'dart:convert';
import '../flutter_sodium.dart';

/// Secret-key single-message authentication using Poly1305.
class OnetimeAuth {
  /// Generates a random key for use in onetime authentication.
  static Future<Uint8List> generateKey() => Sodium.cryptoOnetimeauthKeygen();

  /// Computes a tag for given value and key.
  static Future<Uint8List> compute(Uint8List value, Uint8List key) =>
      Sodium.cryptoOnetimeauth(value, key);

  /// Computes a tag for given string value and key.
  static Future<Uint8List> computeString(String value, Uint8List key) =>
      Sodium.cryptoOnetimeauth(utf8.encode(value), key);

  /// Computes a tag for given stream value and key.
  static Future<Uint8List> computeStream(Stream<String> stream, Uint8List key) async {
    var state = await Sodium.cryptoOnetimeauthInit(key);
    await for (var value in stream) {
      state = await Sodium.cryptoOnetimeauthUpdate(state, utf8.encode(value));
    }
    return await Sodium.cryptoOnetimeauthFinal(state);
  }

  /// Verifies that the tag is valid for given value and key.
  static Future<bool> verify(Uint8List tag, Uint8List value, Uint8List key) =>
      Sodium.cryptoOnetimeauthVerify(tag, value, key);

  /// Verifies that the tag is valid for given string value and key.
  static Future<bool> verifyString(Uint8List tag, String value, Uint8List key) =>
      Sodium.cryptoOnetimeauthVerify(tag, utf8.encode(value), key);
}
