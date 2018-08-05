import 'dart:async';
import 'dart:typed_data';
import '../flutter_sodium.dart';

/// Key exchange API, securely compute a set of shared keys.
class CryptoKx {
  /// Generates a random secret key and a corresponding public key.
  static Future<KeyPair> generateKeyPair() async {
    var map = await Sodium.cryptoKxKeypair();
    return KeyPair.fromMap(map);
  }

  /// Computes a pair of shared keys using the client's public key, the client's secret key and the server's public key.
  static Future<SessionKeys> computeClientSessionKeys(
      KeyPair clientPair, Uint8List serverPublicKey) async {
    final map = await Sodium.cryptoKxClientSessionKeys(
        clientPair.publicKey, clientPair.secretKey, serverPublicKey);
    return SessionKeys.fromMap(map);
  }

  /// Computes a pair of shared keys using the server's public key, the server's secret key and the client's public key.
  static Future<SessionKeys> computeServerSessionKeys(
      KeyPair serverPair, Uint8List clientPublicKey) async {
    final map = await Sodium.cryptoKxServerSessionKeys(
        serverPair.publicKey, serverPair.secretKey, clientPublicKey);
    return SessionKeys.fromMap(map);
  }
}
