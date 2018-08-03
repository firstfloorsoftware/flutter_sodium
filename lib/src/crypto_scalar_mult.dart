import 'dart:async';
import 'dart:typed_data';
import '../flutter_sodium.dart';

/// Performs scalar multiplication of elliptic curve points
class CryptoScalarMult {
  /// Generates a random secret key.
  static Future<Uint8List> generateSecretKey() => RandomBytes.buffer(crypto_box_SECRETKEYBYTES);

  /// Computes a public key given specified secret key.
  static Future<Uint8List> computePublicKey(Uint8List secretKey) =>
      Sodium.cryptoScalarmultBase(secretKey);

  /// Computes a shared secret given a user's secret key and another user's public key.
  static Future<Uint8List> computeSharedSecret(
          Uint8List secretKey, Uint8List publicKey) =>
      Sodium.cryptoScalarmult(secretKey, publicKey);
}
