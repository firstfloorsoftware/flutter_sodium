import 'dart:typed_data';
import 'dart:convert';
import 'key_pair.dart';
import 'sodium.dart';

/// Anonymously send messages to a recipient given its public key.
class SealedBox {
  /// Generates a random secret key and a corresponding public key.
  static KeyPair generateKeyPair() {
    var map = Sodium.cryptoBoxKeypair();
    return KeyPair.fromMap(map);
  }

  /// Encrypts a message for a recipient having specified public key.
  static Uint8List seal(String value, Uint8List publicKey) =>
      Sodium.cryptoBoxSeal(utf8.encode(value), publicKey);

  /// Encrypts a value for a recipient having specified public key.
  static Uint8List sealBytes(Uint8List value, Uint8List publicKey) =>
      Sodium.cryptoBoxSeal(value, publicKey);

  /// Decrypts the ciphertext using given keypair.
  static String sealOpen(Uint8List cipher, KeyPair keys) {
    var message =
        Sodium.cryptoBoxSealOpen(cipher, keys.publicKey, keys.secretKey);

    return utf8.decode(message);
  }

  /// Decrypts the ciphertext using given keypair.
  static Uint8List sealBytesOpen(Uint8List cipher, KeyPair keys) =>
      Sodium.cryptoBoxSealOpen(cipher, keys.publicKey, keys.secretKey);
}
