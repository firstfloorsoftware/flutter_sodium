import 'dart:typed_data';
import 'dart:convert';
import 'package:ffi/ffi.dart';
import 'sodium.dart';

/// Computes a fixed-length fingerprint for an arbitrary long message using the BLAKE2b algorithm.
class GenericHash {
  /// The primitive name.
  static String get primitive => Sodium.cryptoGenerichashPrimitive;

  /// Generates a random key for use with generic hashing.
  static Uint8List randomKey() => Sodium.cryptoGenerichashKeygen();

  /// Computes a generic hash of specified length for given value and optional key.
  static Uint8List hash(Uint8List value, {Uint8List key, int outlen}) {
    outlen ??= Sodium.cryptoGenerichashBytes;
    return Sodium.cryptoGenerichash(outlen, value, key);
  }

  /// Computes a generic hash of specified length for given string value and optional key.
  static Uint8List hashString(String value, {Uint8List key, int outlen}) =>
      hash(utf8.encode(value), key: key, outlen: outlen);

  /// Computes a generic hash of specified length for given stream of byte values and optional key.
  static Future<Uint8List> hashStream(Stream<Uint8List> stream,
      {Uint8List key, int outlen}) async {
    outlen ??= Sodium.cryptoGenerichashBytes;
    final state = Sodium.cryptoGenerichashInit(key, outlen);
    try {
      await for (var value in stream) {
        Sodium.cryptoGenerichashUpdate(state, value);
      }
      return Sodium.cryptoGenerichashFinal(state, outlen);
    } finally {
      free(state);
    }
  }

  /// Computes a generic hash of specified length for given stream of string values and optional key.
  static Future<Uint8List> hashStrings(Stream<String> stream,
      {Uint8List key, int outlen}) async {
    outlen ??= Sodium.cryptoGenerichashBytes;
    final state = Sodium.cryptoGenerichashInit(key, outlen);
    try {
      await for (var value in stream) {
        Sodium.cryptoGenerichashUpdate(state, utf8.encode(value));
      }
      return Sodium.cryptoGenerichashFinal(state, outlen);
    } finally {
      free(state);
    }
  }
}
