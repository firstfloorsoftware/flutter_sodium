import 'dart:async';
import 'dart:typed_data';
import 'dart:convert';
import 'constants.dart';
import '../flutter_sodium.dart';

/// Computes a fixed-length fingerprint for an arbitrary long message using the BLAKE2b algorithm.
class GenericHash {
  /// Generates a random key for use with generic hashing.
  static Future<Uint8List> generateKey() => Sodium.cryptoGenerichashKeygen();

  /// Computes a generic hash of specified length for given value and optional key.
  static Future<Uint8List> hash(Uint8List value,
          {Uint8List key, int outlen = crypto_generichash_BYTES}) =>
      Sodium.cryptoGenerichash(outlen, value, key);

  /// Computes a generic hash of specified length for given value string and optional key.
  static Future<Uint8List> hashString(String value,
          {Uint8List key, int outlen = crypto_generichash_BYTES}) =>
      Sodium.cryptoGenerichash(outlen, utf8.encode(value), key);

  /// Computes a generic hash of specified length for given stream and optional key.
  static Future<Uint8List> hashStream(Stream<String> stream,
      {Uint8List key, int outlen = crypto_generichash_BYTES}) async {
    var state = await Sodium.cryptoGenerichashInit(key, outlen);
    await for (var value in stream) {
      state = await Sodium.cryptoGenerichashUpdate(state, utf8.encode(value));
    }
    return await Sodium.cryptoGenerichashFinal(state, outlen);
  }
}
