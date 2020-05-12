import 'dart:typed_data';
import 'dart:convert';
import 'sodium.dart';

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
        return Sodium.cryptoPwhashAlgArgon2i13;
      case PasswordHashAlgorithm.Argon2id13:
        return Sodium.cryptoPwhashAlgArgon2id13;
      default:
        return Sodium.cryptoPwhashAlgDefault;
    }
  }

  /// The primitive name.
  static String get primitive => Sodium.cryptoPwhashPrimitive;

  /// Generates a random salt for use in password hashing.
  static Uint8List generateSalt() =>
      Sodium.randombytesBuf(Sodium.cryptoPwhashSaltbytes);

  /// Derives a hash from given password and salt.
  static Uint8List hash(String password, Uint8List salt,
      {int outlen,
      int opslimit,
      int memlimit,
      PasswordHashAlgorithm alg = PasswordHashAlgorithm.Default}) {
    outlen ??= Sodium.cryptoPwhashBytesMin;
    opslimit ??= Sodium.cryptoPwhashOpslimitInteractive;
    memlimit ??= Sodium.cryptoPwhashMemlimitInteractive;

    var passwd = utf8.encode(password);

    return Sodium.cryptoPwhash(
        outlen, passwd, salt, opslimit, memlimit, _alg(alg));
  }

  /// Computes a password verification string for given password.
  static String hashStorage(String password, {int opslimit, int memlimit}) {
    opslimit ??= Sodium.cryptoPwhashOpslimitInteractive;
    memlimit ??= Sodium.cryptoPwhashMemlimitInteractive;

    var passwd = utf8.encode(password);
    var hash = Sodium.cryptoPwhashStr(passwd, opslimit, memlimit);
    return ascii.decode(hash);
  }

  /// Computes a password verification string for given password in moderate mode.
  static String hashStorageModerate(String password) => hashStorage(password,
      opslimit: Sodium.cryptoPwhashOpslimitModerate,
      memlimit: Sodium.cryptoPwhashMemlimitModerate);

  /// Computes a password verification string for given password in sensitive mode.
  static String hashStorageSensitive(String password) => hashStorage(password,
      opslimit: Sodium.cryptoPwhashOpslimitSensitive,
      memlimit: Sodium.cryptoPwhashMemlimitSensitive);

  /// Verifies that the storage is a valid password verification string for given password.
  static bool verifyStorage(String storage, String password) {
    var str = ascii.encode(storage);
    var passwd = utf8.encode(password);

    return Sodium.cryptoPwhashStrVerify(str, passwd) == 0;
  }
}
