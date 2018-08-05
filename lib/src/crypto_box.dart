import 'dart:async';
import 'dart:typed_data';
import 'dart:convert';
import '../flutter_sodium.dart';

/// Public-key authenticated encryption
class CryptoBox {
  /// Generates a random secret key and a corresponding public key.
  static Future<KeyPair> generateKeyPair() async {
    var map = await Sodium.cryptoBoxKeypair();
    return KeyPair.fromMap(map);
  }

  /// Generates a random nonce for use with public key-authenticated encryption.
  static Future<Uint8List> generateNonce() =>
      RandomBytes.buffer(crypto_box_NONCEBYTES);

  /// Encrypts a string message with a key and a nonce.
  static Future<Uint8List> encrypt(String value, Uint8List nonce,
          Uint8List publicKey, Uint8List secretKey) =>
      Sodium.cryptoBoxEasy(utf8.encode(value), nonce, publicKey, secretKey);

  /// Encrypts a message with a key and a nonce.
  static Future<Uint8List> encryptBytes(Uint8List value, Uint8List nonce,
          Uint8List publicKey, Uint8List secretKey) =>
      Sodium.cryptoBoxEasy(value, nonce, publicKey, secretKey);

  /// Verifies and decrypts a cipher text produced by encrypt.
  static Future<String> decrypt(Uint8List cipherText, Uint8List nonce,
      Uint8List publicKey, Uint8List secretKey) async {
    final message =
        await Sodium.cryptoBoxOpenEasy(cipherText, nonce, publicKey, secretKey);
    return utf8.decode(message);
  }

  /// Verifies and decrypts a cipher text produced by encrypt.
  static Future<Uint8List> decryptBytes(Uint8List cipherText, Uint8List nonce,
          Uint8List publicKey, Uint8List secretKey) =>
      Sodium.cryptoBoxOpenEasy(cipherText, nonce, publicKey, secretKey);

  /// Encrypts a string message with a key and a nonce, returning the encrypted message and authentication tag
  static Future<DetachedCipher> encryptDetached(String value, Uint8List nonce,
      Uint8List publicKey, Uint8List secretKey) async {
    var map = await Sodium.cryptoBoxDetached(
        utf8.encode(value), nonce, publicKey, secretKey);
    return DetachedCipher.fromMap(map);
  }

  /// Encrypts a message with a key and a nonce, returning the encrypted message and authentication tag
  static Future<DetachedCipher> encryptBytesDetached(Uint8List value,
      Uint8List nonce, Uint8List publicKey, Uint8List secretKey) async {
    var map =
        await Sodium.cryptoBoxDetached(value, nonce, publicKey, secretKey);
    return DetachedCipher.fromMap(map);
  }

  /// Verifies and decrypts a detached cipher text and tag.
  static Future<String> decryptDetached(DetachedCipher cipher, Uint8List nonce,
      Uint8List publicKey, Uint8List secretKey) async {
    final message = await Sodium.cryptoBoxOpenDetached(
        cipher.cipher, cipher.mac, nonce, publicKey, secretKey);
    return utf8.decode(message);
  }

  /// Verifies and decrypts a detached cipher text and tag.
  static Future<Uint8List> decryptBytesDetached(DetachedCipher cipher,
          Uint8List nonce, Uint8List publicKey, Uint8List secretKey) =>
      Sodium.cryptoBoxOpenDetached(
          cipher.cipher, cipher.mac, nonce, publicKey, secretKey);
}
