import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import '../flutter_sodium.dart';
import 'key_pair.dart';

/// Anonymously send messages to a recipient given its public key.
class SealedBox {
  /// Generates a random secret key and a corresponding public key.
  static Future<KeyPair> generateKeyPair() async {
    var map = await Sodium.cryptoBoxKeypair();
    return KeyPair.fromMap(map);
  }

  /// Encrypts a message for a recipient having specified public key.
  static Future<Uint8List> seal(String value, Uint8List publicKey) =>
      Sodium.cryptoBoxSeal(utf8.encode(value), publicKey);

  /// Encrypts a value for a recipient having specified public key.
  static Future<Uint8List> sealBytes(Uint8List value, Uint8List publicKey) =>
      Sodium.cryptoBoxSeal(value, publicKey);

  /// Decrypts the ciphertext using given keypair.
  static Future<String> open(Uint8List cipher, KeyPair keyPair) async {
    var message = await Sodium.cryptoBoxSealOpen(
        cipher, keyPair.publicKey, keyPair.secretKey);

    return utf8.decode(message);
  }

  /// Decrypts the ciphertext using given keypair.
  static Future<Uint8List> openBytes(Uint8List cipher, KeyPair keyPair) =>
      Sodium.cryptoBoxSealOpen(cipher, keyPair.publicKey, keyPair.secretKey);
}
