import 'dart:typed_data';
import 'sodium.dart';

/// Provides a set of functions to generate unpredictable data, suitable for creating secret keys
class RandomBytes {
  /// The name of the random bytes implementation.
  static String get implementationName => Sodium.randombytesImplementationName;

  /// Generates an unpredictable value between 0 and 0xffffffff (included).
  static int random() => Sodium.randombytesRandom();

  /// Generates an unpredictable value between 0 and upperBound (excluded)
  static int uniform(int upperBound) => Sodium.randombytesUniform(upperBound);

  /// Generates an unpredictable sequence of bytes of specified size.
  static Uint8List buffer(int size) => Sodium.randombytesBuf(size);

  /// Generates a sequence of bytes of specified size. For a given seed, this function will always output the same sequence
  static Uint8List bufferDeterministic(int size, Uint8List seed) =>
      Sodium.randombytesBufDeterministic(size, seed);
}
