import 'dart:async';
import 'dart:typed_data';
import 'dart:convert';
import '../flutter_sodium.dart';

/// Computes a signature for a message using a secret key, and provides verification using a public key.
class CryptoSign {
  /// Generates a random key for use with public-key signatures.
  static Future<KeyPair> generateKeyPair() async {
    var map = await Sodium.cryptoSignKeypair();
    return KeyPair.fromMap(map);
  }

  /// Prepends a signature to specified message for given secret key.
  static Future<Uint8List> signCombined(
          Uint8List message, Uint8List secretKey) =>
      Sodium.cryptoSign(message, secretKey);

  /// Computes a signature for given string value and secret key.
  static Future<Uint8List> sign(String message, Uint8List secretKey) =>
      Sodium.cryptoSignDetached(utf8.encode(message), secretKey);

  /// Computes a signature for given message and secret key.
  static Future<Uint8List> signBytes(Uint8List message, Uint8List secretKey) =>
      Sodium.cryptoSignDetached(message, secretKey);

  /// Computes a signature for given stream value and secret key.
  static Future<Uint8List> signStream(
      Stream<String> stream, Uint8List secretKey) async {
    var state = await Sodium.cryptoSignInit();
    await for (var value in stream) {
      state = await Sodium.cryptoSignUpdate(state, utf8.encode(value));
    }
    return await Sodium.cryptoSignFinalCreate(state, secretKey);
  }

  /// Checks the signed message using given public key and returns the message with the signature removed.
  static Future<Uint8List> open(Uint8List signedMessage, Uint8List publicKey) =>
      Sodium.cryptoSignOpen(signedMessage, publicKey);

  /// Verifies whether the signature is valid for given string message using the signer's public key.
  static Future<bool> verify(
          Uint8List signature, String message, Uint8List publicKey) =>
      Sodium.cryptoSignVerifyDetached(
          signature, utf8.encode(message), publicKey);

  /// Verifies whether the signature is valid for given message using the signer's public key.
  static Future<bool> verifyBytes(
          Uint8List signature, Uint8List message, Uint8List publicKey) =>
      Sodium.cryptoSignVerifyDetached(signature, message, publicKey);

  /// Verifies whether the signature is valid for given stream meage using the signer's public key.
  static Future<bool> verifyStream(
      Uint8List signature, Stream<String> stream, Uint8List publicKey) async {
    var state = await Sodium.cryptoSignInit();
    await for (var value in stream) {
      state = await Sodium.cryptoSignUpdate(state, utf8.encode(value));
    }
    return await Sodium.cryptoSignFinalVerify(state, signature, publicKey);
  }
}
