import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import '../flutter_sodium.dart';

/// Detached cipher and associated authentication tag.
class DetachedCipher {
  final Uint8List cipher;
  final Uint8List mac;

  const DetachedCipher(this.cipher, this.mac);
  DetachedCipher.fromMap(Map<Uint8List, Uint8List> map)
      : this(map['c'], map['mac']);
}

/// Encrypts a message with a key and a nonce and computes an authentication tag.
class SecretBox {
  /// Generates a random key for use with secret key encryption.
  static Future<Uint8List> generateKey() => Sodium.cryptoSecretboxKeygen();

  /// Generates a random nonce for use with secret key encryption.
  static Future<Uint8List> generateNonce() => Randombytes.buffer(crypto_secretbox_NONCEBYTES);

  /// Encrypts a string message with a key and a nonce.
  static Future<Uint8List> encrypt(
          String value, Uint8List nonce, Uint8List key) =>
      Sodium.cryptoSecretboxEasy(utf8.encode(value), nonce, key);

  /// Encrypts a message with a key and a nonce.
  static Future<Uint8List> encryptBytes(
          Uint8List value, Uint8List nonce, Uint8List key) =>
      Sodium.cryptoSecretboxEasy(value, nonce, key);

  /// Verifies and decrypts a cipher text produced by encrypt.
  static Future<String> decrypt(
      Uint8List cipherText, Uint8List nonce, Uint8List key) async {
    final message =
        await Sodium.cryptoSecretboxOpenEasy(cipherText, nonce, key);
    return utf8.decode(message);
  }

  /// Verifies and decrypts a cipher text produced by encrypt.
  static Future<Uint8List> decryptBytes(
          Uint8List cipherText, Uint8List nonce, Uint8List key) =>
      Sodium.cryptoSecretboxOpenEasy(cipherText, nonce, key);

  /// Encrypts a string message with a key and a nonce, returning the encrypted message and authentication tag
  static Future<DetachedCipher> encryptDetached(
      String value, Uint8List nonce, Uint8List key) async {
    var map =
        await Sodium.cryptoSecretboxDetached(utf8.encode(value), nonce, key);
    return DetachedCipher.fromMap(map);
  }

  /// Encrypts a message with a key and a nonce, returning the encrypted message and authentication tag
  static Future<DetachedCipher> encryptBytesDetached(
      Uint8List value, Uint8List nonce, Uint8List key) async {
    var map = await Sodium.cryptoSecretboxDetached(value, nonce, key);
    return DetachedCipher.fromMap(map);
  }

  /// Verifies and decrypts a detached cipher text and tag.
  static Future<String> decryptDetached(
      DetachedCipher cipher, Uint8List nonce, Uint8List key) async {
    final message = await Sodium.cryptoSecretboxOpenDetached(
        cipher.cipher, cipher.mac, nonce, key);
    return utf8.decode(message);
  }

  /// Verifies and decrypts a detached cipher text and tag.
  static Future<Uint8List> decryptBytesDetached(
          DetachedCipher cipher, Uint8List nonce, Uint8List key) =>
      Sodium.cryptoSecretboxOpenDetached(cipher.cipher, cipher.mac, nonce, key);
}
