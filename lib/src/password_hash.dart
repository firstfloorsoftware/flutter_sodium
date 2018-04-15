import 'dart:async';
import 'dart:typed_data';
import 'dart:convert';
import 'constants.dart';
import '../flutter_sodium.dart';

/// Defines the supported password hashing algorithms.
enum PasswordHashAlgorithm {
  /// The recommended algoritm.
  Default,

  /// Version 1.3 of the Argon2i algorithm.
  Argon2i13,

  /// Version 1.3 of the Argon2id algorithm.
  Argon2id13
}

/// Provides an Argon2 password hashing scheme implementation.
class PasswordHash {
  static int _alg(PasswordHashAlgorithm alg) {
    switch (alg) {
      case PasswordHashAlgorithm.Argon2i13:
        return crypto_pwhash_ALG_ARGON2I13;
      case PasswordHashAlgorithm.Argon2id13:
        return crypto_pwhash_ALG_ARGON2ID13;
      default:
        return crypto_pwhash_ALG_DEFAULT;
    }
  }

  /// Generates a random salt for use in password hashing.
  static Future<Uint8List> generateSalt() =>
      Sodium.randombytesBuf(crypto_pwhash_SALTBYTES);

  /// Derives a hash from given password and salt.
  static Future<Uint8List> hash(String password, Uint8List salt,
      {int outlen = crypto_pwhash_BYTES_MIN,
      int opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE,
      int memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE,
      PasswordHashAlgorithm alg = PasswordHashAlgorithm.Default}) {
    var passwd = utf8.encode(password);

    return Sodium.cryptoPwhash(
        outlen, passwd, salt, opslimit, memlimit, _alg(alg));
  }

  /// Computes a password verification string for given password.
  static Future<String> hashStorage(String password,
      {int opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE,
      int memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE}) async {
    var passwd = utf8.encode(password);
    var hash = await Sodium.cryptoPwhashStr(passwd, opslimit, memlimit);
    return ascii.decode(hash);
  }

  /// Verifies that the storage is a valid password verification string for given password.
  static Future<bool> verifyStorage(String storage, String password) {
    var str = ascii.encode(storage);
    var passwd = utf8.encode(password);

    return Sodium.cryptoPwhashStrVerify(str, passwd);
  }
}
