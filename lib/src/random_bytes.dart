import 'dart:async';
import 'dart:typed_data';
import '../flutter_sodium.dart';

/// Provides a set of functions to generate unpredictable data, suitable for creating secret keys
class RandomBytes {
  /// Generates an unpredictable value between 0 and 0xffffffff (included).
  static Future<int> random() => Sodium.randombytesRandom();

  /// Generates an unpredictable value between 0 and upperBound (excluded)
  static Future<int> uniform(int upperBound) =>
      Sodium.randombytesUniform(upperBound);

  /// Generates an unpredictable sequence of bytes of specified size.
  static Future<Uint8List> buffer(int size) => Sodium.randombytesBuf(size);

  /// Generates a sequence of bytes of specified size. For a given seed, this function will always output the same sequence
  static Future<Uint8List> bufferDeterministic(int size, Uint8List seed) =>
      Sodium.randombytesBufDeterministic(size, seed);
}
