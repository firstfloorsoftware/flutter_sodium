import 'dart:typed_data';
import 'key_pair.dart';
import 'session_keys.dart';
import 'sodium.dart';

/// Key exchange API, securely compute a set of shared keys.
class KeyExchange {
  /// Generates a random secret key and a corresponding public key.
  static KeyPair randomKeys() {
    final map = Sodium.cryptoKxKeypair();
    return KeyPair.fromMap(map);
  }

  /// Generates a random seed for use in seedKeys.
  static Uint8List randomSeed() =>
      Sodium.randombytesBuf(Sodium.cryptoKxSeedbytes);

  /// Generates a secret key and a corresponding public key using given seed.
  static KeyPair seedKeys(Uint8List seed) {
    final map = Sodium.cryptoKxSeedKeypair(seed);
    return KeyPair.fromMap(map);
  }

  /// Computes a pair of shared keys using the client's public key, the client's secret key and the server's public key.
  static SessionKeys computeClientSessionKeys(
      KeyPair clientPair, Uint8List serverPublicKey) {
    final map = Sodium.cryptoKxClientSessionKeys(
        clientPair.publicKey, clientPair.secretKey, serverPublicKey);
    return SessionKeys.fromMap(map);
  }

  /// Computes a pair of shared keys using the server's public key, the server's secret key and the client's public key.
  static SessionKeys computeServerSessionKeys(
      KeyPair serverPair, Uint8List clientPublicKey) {
    final map = Sodium.cryptoKxServerSessionKeys(
        serverPair.publicKey, serverPair.secretKey, clientPublicKey);
    return SessionKeys.fromMap(map);
  }
}
