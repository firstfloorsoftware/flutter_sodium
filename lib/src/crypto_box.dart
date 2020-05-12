import 'dart:typed_data';
import 'dart:convert';
import 'detached_cipher.dart';
import 'key_pair.dart';
import 'sodium.dart';

/// Public-key authenticated encryption
class CryptoBox {
  /// The primitive name.
  static String get primitive => Sodium.cryptoBoxPrimitive;

  /// Generates a random secret key and a corresponding public key.
  static KeyPair generateKeyPair() {
    final map = Sodium.cryptoBoxKeypair();
    return KeyPair.fromMap(map);
  }

  /// Generates a random nonce for use with public key-authenticated encryption.
  static Uint8List generateNonce() =>
      Sodium.randombytesBuf(Sodium.cryptoBoxNoncebytes);

  /// Computes a shared secret key given a public key and a secret key for use in precalculation interface.
  static Uint8List computeSharedKey(Uint8List pk, Uint8List sk) =>
      Sodium.cryptoBoxBeforenm(pk, sk);

  /// Encrypts a string message with a key and a nonce.
  static Uint8List encrypt(String value, Uint8List nonce, Uint8List publicKey,
          Uint8List secretKey) =>
      Sodium.cryptoBoxEasy(utf8.encode(value), nonce, publicKey, secretKey);

  /// Encrypts a message with a key and a nonce.
  static Uint8List encryptBytes(Uint8List value, Uint8List nonce,
          Uint8List publicKey, Uint8List secretKey) =>
      Sodium.cryptoBoxEasy(value, nonce, publicKey, secretKey);

  /// Verifies and decrypts a cipher text produced by encrypt.
  static String decrypt(Uint8List cipherText, Uint8List nonce,
      Uint8List publicKey, Uint8List secretKey) {
    final message =
        Sodium.cryptoBoxOpenEasy(cipherText, nonce, publicKey, secretKey);
    return utf8.decode(message);
  }

  /// Verifies and decrypts a cipher text produced by encrypt.
  static Uint8List decryptBytes(Uint8List cipherText, Uint8List nonce,
          Uint8List publicKey, Uint8List secretKey) =>
      Sodium.cryptoBoxOpenEasy(cipherText, nonce, publicKey, secretKey);

  /// Encrypts a string message with a key and a nonce, returning the encrypted message and authentication tag
  static DetachedCipher encryptDetached(
      String value, Uint8List nonce, Uint8List publicKey, Uint8List secretKey) {
    var map = Sodium.cryptoBoxDetached(
        utf8.encode(value), nonce, publicKey, secretKey);
    return DetachedCipher.fromMap(map);
  }

  /// Encrypts a message with a key and a nonce, returning the encrypted message and authentication tag
  static DetachedCipher encryptBytesDetached(Uint8List value, Uint8List nonce,
      Uint8List publicKey, Uint8List secretKey) {
    var map = Sodium.cryptoBoxDetached(value, nonce, publicKey, secretKey);
    return DetachedCipher.fromMap(map);
  }

  /// Verifies and decrypts a detached cipher text and tag.
  static String decryptDetached(DetachedCipher cipher, Uint8List nonce,
      Uint8List publicKey, Uint8List secretKey) {
    final message = Sodium.cryptoBoxOpenDetached(
        cipher.cipher, cipher.mac, nonce, publicKey, secretKey);
    return utf8.decode(message);
  }

  /// Verifies and decrypts a detached cipher text and tag.
  static Uint8List decryptBytesDetached(DetachedCipher cipher, Uint8List nonce,
          Uint8List publicKey, Uint8List secretKey) =>
      Sodium.cryptoBoxOpenDetached(
          cipher.cipher, cipher.mac, nonce, publicKey, secretKey);

  /// Encrypts a string message with a key and a nonce.
  static Uint8List encryptAfternm(String value, Uint8List nonce, Uint8List k) =>
      Sodium.cryptoBoxEasyAfternm(utf8.encode(value), nonce, k);

  /// Encrypts a message with a key and a nonce.
  static Uint8List encryptBytesAfternm(
          Uint8List value, Uint8List nonce, Uint8List k) =>
      Sodium.cryptoBoxEasyAfternm(value, nonce, k);

  /// Verifies and decrypts a cipher text produced by encrypt.
  static String decryptAfternm(
      Uint8List cipherText, Uint8List nonce, Uint8List k) {
    final message = Sodium.cryptoBoxOpenEasyAfternm(cipherText, nonce, k);
    return utf8.decode(message);
  }

  /// Verifies and decrypts a cipher text produced by encrypt.
  static Uint8List decryptBytesAfternm(
          Uint8List cipherText, Uint8List nonce, Uint8List k) =>
      Sodium.cryptoBoxOpenEasyAfternm(cipherText, nonce, k);

  /// Encrypts a string message with a key and a nonce, returning the encrypted message and authentication tag
  static DetachedCipher encryptDetachedAfternm(
      String value, Uint8List nonce, Uint8List k) {
    var map = Sodium.cryptoBoxDetachedAfternm(utf8.encode(value), nonce, k);
    return DetachedCipher.fromMap(map);
  }

  /// Encrypts a message with a key and a nonce, returning the encrypted message and authentication tag
  static DetachedCipher encryptBytesDetachedAfternm(
      Uint8List value, Uint8List nonce, Uint8List k) {
    var map = Sodium.cryptoBoxDetachedAfternm(value, nonce, k);
    return DetachedCipher.fromMap(map);
  }

  /// Verifies and decrypts a detached cipher text and tag.
  static String decryptDetachedAfternm(
      DetachedCipher cipher, Uint8List nonce, Uint8List k) {
    final message = Sodium.cryptoBoxOpenDetachedAfternm(
        cipher.cipher, cipher.mac, nonce, k);
    return utf8.decode(message);
  }

  /// Verifies and decrypts a detached cipher text and tag.
  static Uint8List decryptBytesDetachedAfternm(
          DetachedCipher cipher, Uint8List nonce, Uint8List k) =>
      Sodium.cryptoBoxOpenDetachedAfternm(cipher.cipher, cipher.mac, nonce, k);
}
