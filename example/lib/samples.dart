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

void box1(Function(Object) print) {
  // BEGIN box1: Combined mode: The authentication tag and the encrypted message are stored together.
  // Generate key pairs
  final alice = CryptoBox.generateKeyPair();
  final bob = CryptoBox.generateKeyPair();
  final nonce = CryptoBox.generateNonce();

  // Alice encrypts message for Bob
  final msg = 'hello world';
  final encrypted =
      CryptoBox.encrypt(msg, nonce, bob.publicKey, alice.secretKey);

  print(hex.encode(encrypted));

  // Bob decrypts message from Alice
  final decrypted =
      CryptoBox.decrypt(encrypted, nonce, alice.publicKey, bob.secretKey);

  assert(msg == decrypted);
  print('decrypted: $decrypted');
  // END box1
}

void box2(Function(Object) print) {
  // BEGIN box2: Detached mode: The authentication tag and the encrypted message are detached so they can be stored at different locations.
  // Generate key pairs
  final alice = CryptoBox.generateKeyPair();
  final bob = CryptoBox.generateKeyPair();
  final nonce = CryptoBox.generateNonce();

  // Alice encrypts message for Bob
  final msg = 'hello world';
  final encrypted =
      CryptoBox.encryptDetached(msg, nonce, bob.publicKey, alice.secretKey);

  print('cipher: ${hex.encode(encrypted.cipher)}');
  print('mac: ${hex.encode(encrypted.mac)}');

  // Bob decrypts message from Alice
  final decrypted = CryptoBox.decryptDetached(
      encrypted, nonce, alice.publicKey, bob.secretKey);

  assert(msg == decrypted);
  print('decrypted: $decrypted');
  // END box2
}

void box3(Function(Object) print) {
  // BEGIN box3: Precalculated combined mode: The authentication tag and the encrypted message are stored together.
  // Generate key pairs
  final alice = CryptoBox.generateKeyPair();
  final bob = CryptoBox.generateKeyPair();
  final nonce = CryptoBox.generateNonce();

  // Alice encrypts message for Bob
  final msg = 'hello world';
  final encrypted =
      CryptoBox.encrypt(msg, nonce, bob.publicKey, alice.secretKey);

  print(hex.encode(encrypted));

  // Bob decrypts message from Alice (precalculated)
  final key = CryptoBox.computeSharedKey(alice.publicKey, bob.secretKey);
  final decrypted = CryptoBox.decryptAfternm(encrypted, nonce, key);

  assert(msg == decrypted);
  print('decrypted: $decrypted');
  // END box3
}

void box4(Function(Object) print) {
  // BEGIN box4: Precalculated detached mode: The authentication tag and the encrypted message are detached so they can be stored at different locations.
  // Generate key pairs
  final alice = CryptoBox.generateKeyPair();
  final bob = CryptoBox.generateKeyPair();
  final nonce = CryptoBox.generateNonce();

  // Alice encrypts message for Bob (precalculated)
  final key = CryptoBox.computeSharedKey(bob.publicKey, alice.secretKey);
  final msg = 'hello world';
  final encrypted = CryptoBox.encryptDetachedAfternm(msg, nonce, key);

  print('cipher: ${hex.encode(encrypted.cipher)}');
  print('mac: ${hex.encode(encrypted.mac)}');

  // Bob decrypts message from Alice
  final decrypted = CryptoBox.decryptDetached(
      encrypted, nonce, alice.publicKey, bob.secretKey);

  assert(msg == decrypted);
  print('decrypted: $decrypted');
  // END box4
}

void box5(Function(Object) print) {
  // BEGIN box5: Usage: Anonymous sender encrypts a message intended for recipient only.
  // Recipient creates a long-term key pair
  final keys = SealedBox.generateKeyPair();

  // Anonymous sender encrypts a message using an ephemeral key pair and the recipient's public key
  final msg = 'hello world';
  final cipher = SealedBox.seal(msg, keys.publicKey);

  print('cipher: ${hex.encode(cipher)}');

  // Recipient decrypts the ciphertext
  final decrypted = SealedBox.sealOpen(cipher, keys);

  assert(msg == decrypted);
  print('decrypted: $decrypted');
  // END box5
}

void generic1(Function(Object) print) {
  // BEGIN generic1: Single-part without a key:
  final value = 'Arbitrary data to hash';
  final hash = GenericHash.hash(value);

  print(hex.encode(hash));
  // END generic1
}

void generic2(Function(Object) print) {
  // BEGIN generic2: Single-part with a key:
  final value = 'Arbitrary data to hash';
  final key = GenericHash.generateKey();

  final hash = GenericHash.hash(value, key: key);

  print(hex.encode(hash));
  // END generic2
}

Future generic3(Function(Object) print) async {
  // BEGIN generic3: Multi-part without a key: Should result in a hash equal to the single-part without a key sample.
  final stream = Stream.fromIterable(['Arbitrary data ', 'to hash']);

  final hash = await GenericHash.hashStream(stream);

  print(hex.encode(hash));
  // END generic3
}

Future generic4(Function(Object) print) async {
  // BEGIN generic4: Multi-part with a key:
  final stream = Stream.fromIterable(
      ['Arbitrary data to hash', 'is longer than expected']);
  final key = GenericHash.generateKey();

  final hash = await GenericHash.hashStream(stream, key: key);

  print(hex.encode(hash));
  // END generic4
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
