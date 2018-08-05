import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import '../flutter_sodium.dart';

/// Derive secret subkeys from a single master key.
class KeyDerivation {
  /// Generates a random master key for use with key derivation.
  static Future<Uint8List> generateKey() => Sodium.cryptoKdfKeygen();

  /// Derives a subkey from given master key.
  static Future<Uint8List> deriveFromKey(Uint8List masterKey, int subKeyId,
          {int subKeyLength = crypto_kdf_BYTES_MIN,
          String context = '00000000'}) =>
      Sodium.cryptoKdfDeriveFromKey(
          subKeyLength, subKeyId, utf8.encode(context), masterKey);
}
