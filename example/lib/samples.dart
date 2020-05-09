import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:convert/convert.dart';
import 'package:flutter_sodium/flutter_sodium.dart';

final salt = PasswordHash.generateSalt();

void api1(Function(Object) print) {
  // BEGIN api1: Core API: Compute a password hash using the Core API with predefined salt.
  final pw = utf8.encode('hello world');
  final hash = Sodium.cryptoPwhash(
      Sodium.cryptoPwhashBytesMin,
      pw,
      salt,
      Sodium.cryptoPwhashOpslimitInteractive,
      Sodium.cryptoPwhashMemlimitInteractive,
      Sodium.cryptoPwhashAlgDefault);

  print('salt: ${hex.encode(salt)}');
  print('hash: ${hex.encode(hash)}');
  // END api1
}

void api2(Function(Object) print) {
  // BEGIN api2: High-level API: Compute a password hash using the high-level API with predefined salt.
  final pw = 'hello world';
  final hash = PasswordHash.hash(pw, salt);

  print('salt: ${hex.encode(salt)}');
  print('hash: ${hex.encode(hash)}');
  // END api2
}

void random1(Function(Object) print) {
  // BEGIN random1: Random: Returns an unpredictable value between 0 and 0xffffffff (included).
  final rnd = RandomBytes.random();
  print(rnd.toRadixString(16));
  // END random1
}

void random2(Function(Object) print) {
  // BEGIN random2: Uniform: Generates an unpredictable value between 0 and upperBound (excluded)
  final rnd = RandomBytes.uniform(16);
  print(rnd);
  // END random2
}

void random3(Function(Object) print) {
  // BEGIN random3: Buffer: Generates an unpredictable sequence of bytes of specified size.
  final buf = RandomBytes.buffer(16);
  print(hex.encode(buf));
  // END random3
}

void version1(Function(Object) print) {
  // BEGIN version1: Usage: Retrieves the version details of the loaded libsodium library.
  final version = Sodium.sodiumVersionString;
  final major = Sodium.sodiumLibraryVersionMajor;
  final minor = Sodium.sodiumLibraryVersionMinor;

  print('$version ($major.$minor)');
  // END version1
}

void generic1(Function(Object) print) {
  // BEGIN generic1: Usage: Computes a fixed-length fingerprint for an arbitrary long message using the BLAKE2b algorithm.
  final value = 'hello world';
  final hash = GenericHash.hash(value);

  print(hex.encode(hash));
  // END generic1
}

void generic2(Function(Object) print) {
  // BEGIN generic2: Key and outlen: Computes a generic hash of specified length for given string value and key.
  final value = 'hello world';
  final key = GenericHash.generateKey();
  final outlen = 16;

  final hash = GenericHash.hash(value, key: key, outlen: outlen);

  print(hex.encode(hash));
  // END generic2
}

void pwhash1(Function(Object) print) {
  // BEGIN pwhash1: Hash: Derives a hash from given password and salt.
  final pw = 'hello world';
  final salt = PasswordHash.generateSalt();
  final hash = PasswordHash.hash(pw, salt);

  print(hex.encode(hash));
  // END pwhash1
}

void pwhash2(Function(Object) print) {
  // BEGIN pwhash2: Hash storage: Computes a password verification string for given password.
  final pw = 'hello world';
  final str = PasswordHash.hashStorage(pw);
  print(str);

  // verify storage string
  final valid = PasswordHash.verifyStorage(str, pw);
  print('Valid: $valid');
  // END pwhash2
}

Future pwhash3(Function(Object) print) async {
  // BEGIN pwhash3: Hash storage async: Execute long running hash operation in background using Flutter's compute.
  // time operation
  final watch = Stopwatch();
  watch.start();

  // compute hash
  final pw = 'hello world';
  final str = await compute(PasswordHash.hashStorageModerate, pw);

  print(str);
  print('Compute took ${watch.elapsedMilliseconds}ms');
  watch.stop();
  // END pwhash3
}
