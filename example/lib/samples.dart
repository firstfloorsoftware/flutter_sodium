import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:flutter_sodium/flutter_sodium.dart';

class Samples {
  final salt = PasswordHash.randomSalt();

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
    final hash = PasswordHash.hashString(pw, salt);

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

  void version2(Function(Object) print) {
    // BEGIN version2: Primitives: Retrieves the names of the algorithms used in the various libsodium APIs.
    final cryptoBox = Sodium.cryptoBoxPrimitive;
    final generichash = Sodium.cryptoGenerichashPrimitive;
    final pwhash = Sodium.cryptoPwhashPrimitive;
    final sign = Sodium.cryptoSignPrimitive;

    print('crypto_box: $cryptoBox');
    print('crypto_generichash: $generichash');
    print('crypto_pwhash: $pwhash');
    print('crypto_sign: $sign');
    // END version2
  }

  void box1(Function(Object) print) {
    // BEGIN box1: Combined mode: The authentication tag and the encrypted message are stored together.
    // Generate key pairs
    final alice = CryptoBox.randomKeys();
    final bob = CryptoBox.randomKeys();
    final nonce = CryptoBox.randomNonce();

    // Alice encrypts message for Bob
    final msg = 'hello world';
    final encrypted =
        CryptoBox.encryptString(msg, nonce, bob.publicKey, alice.secretKey);

    print(hex.encode(encrypted));

    // Bob decrypts message from Alice
    final decrypted = CryptoBox.decryptString(
        encrypted, nonce, alice.publicKey, bob.secretKey);

    assert(msg == decrypted);
    print('decrypted: $decrypted');
    // END box1
  }

  void box2(Function(Object) print) {
    // BEGIN box2: Detached mode: The authentication tag and the encrypted message are detached so they can be stored at different locations.
    // Generate key pairs
    final alice = CryptoBox.randomKeys();
    final bob = CryptoBox.randomKeys();
    final nonce = CryptoBox.randomNonce();

    // Alice encrypts message for Bob
    final msg = 'hello world';
    final encrypted = CryptoBox.encryptStringDetached(
        msg, nonce, bob.publicKey, alice.secretKey);

    print('cipher: ${hex.encode(encrypted.cipher)}');
    print('mac: ${hex.encode(encrypted.mac)}');

    // Bob decrypts message from Alice
    final decrypted = CryptoBox.decryptStringDetached(
        encrypted, nonce, alice.publicKey, bob.secretKey);

    assert(msg == decrypted);
    print('decrypted: $decrypted');
    // END box2
  }

  void box3(Function(Object) print) {
    // BEGIN box3: Precalculated combined mode: The authentication tag and the encrypted message are stored together.
    // Generate key pairs
    final alice = CryptoBox.randomKeys();
    final bob = CryptoBox.randomKeys();
    final nonce = CryptoBox.randomNonce();

    // Alice encrypts message for Bob
    final msg = 'hello world';
    final encrypted =
        CryptoBox.encryptString(msg, nonce, bob.publicKey, alice.secretKey);

    print(hex.encode(encrypted));

    // Bob decrypts message from Alice (precalculated)
    final key = CryptoBox.sharedSecret(alice.publicKey, bob.secretKey);
    final decrypted = CryptoBox.decryptStringAfternm(encrypted, nonce, key);

    assert(msg == decrypted);
    print('decrypted: $decrypted');
    // END box3
  }

  void box4(Function(Object) print) {
    // BEGIN box4: Precalculated detached mode: The authentication tag and the encrypted message are detached so they can be stored at different locations.
    // Generate key pairs
    final alice = CryptoBox.randomKeys();
    final bob = CryptoBox.randomKeys();
    final nonce = CryptoBox.randomNonce();

    // Alice encrypts message for Bob (precalculated)
    final key = CryptoBox.sharedSecret(bob.publicKey, alice.secretKey);
    final msg = 'hello world';
    final encrypted = CryptoBox.encryptStringDetachedAfternm(msg, nonce, key);

    print('cipher: ${hex.encode(encrypted.cipher)}');
    print('mac: ${hex.encode(encrypted.mac)}');

    // Bob decrypts message from Alice
    final decrypted = CryptoBox.decryptStringDetached(
        encrypted, nonce, alice.publicKey, bob.secretKey);

    assert(msg == decrypted);
    print('decrypted: $decrypted');
    // END box4
  }

  void box5(Function(Object) print) {
    // BEGIN box5: Usage: Anonymous sender encrypts a message intended for recipient only.
    // Recipient creates a long-term key pair
    final keys = SealedBox.randomKeys();

    // Anonymous sender encrypts a message using an ephemeral key pair and the recipient's public key
    final msg = 'hello world';
    final cipher = SealedBox.sealString(msg, keys.publicKey);

    print('cipher: ${hex.encode(cipher)}');

    // Recipient decrypts the ciphertext
    final decrypted = SealedBox.openString(cipher, keys);

    assert(msg == decrypted);
    print('decrypted: $decrypted');
    // END box5
  }

  void sign1(Function(Object) print) {
    // BEGIN sign1: Combined mode: Compute a signed message
    final msg = 'hello world';
    final keys = CryptoSign.randomKeys();

    // sign with secret key
    final signed = CryptoSign.signString(msg, keys.secretKey);
    print('signed: ${hex.encode(signed)}');

    // verify with public key
    final unsigned = CryptoSign.openString(signed, keys.publicKey);
    print('unsigned: $unsigned');

    assert(msg == unsigned);
    // END sign1
  }

  void sign2(Function(Object) print) {
    // BEGIN sign2: Detached mode: Compute a signature
    // Author generates keypair
    final keys = CryptoSign.randomKeys();

    // Author computes signature using secret key
    final msg = 'hello world';
    final sig = CryptoSign.signStringDetached(msg, keys.secretKey);
    print(hex.encode(sig));

    // Recipient verifies message was issued by author using public key
    final valid = CryptoSign.verifyString(sig, msg, keys.publicKey);

    assert(valid);
    // END sign2
  }

  Future sign3(Function(Object) print) async {
    // BEGIN sign3: Multi-part message: Compute a signature for multiple messages.
    // Author generates keypair
    final keys = CryptoSign.randomKeys();

    // Author computes signature using secret key
    final parts = ['Arbitrary data to hash', 'is longer than expected'];
    final sig = await CryptoSign.signStrings(
        Stream.fromIterable(parts), keys.secretKey);
    print(hex.encode(sig));

    // Recipient verifies message was issued by author using public key
    final valid = await CryptoSign.verifyStrings(
        sig, Stream.fromIterable(parts), keys.publicKey);

    assert(valid);
    // END sign3
  }

  void sign4(Function(Object) print) {
    // BEGIN sign4: Secret key extraction: Extracts seed and public key from a secret key.
    final seed = CryptoSign.randomSeed();
    final keys = CryptoSign.seedKeys(seed);

    print('seed: ${hex.encode(seed)}');
    print('pk: ${hex.encode(keys.publicKey)}');
    print('sk: ${hex.encode(keys.secretKey)}');

    final s = CryptoSign.extractSeed(keys.secretKey);
    final pk = CryptoSign.extractPublicKey(keys.secretKey);

    // assert equality
    final eq = ListEquality().equals;
    assert(eq(s, seed));
    assert(eq(pk, keys.publicKey));
    // END sign4
  }

  void generic1(Function(Object) print) {
    // BEGIN generic1: Single-part without a key:
    final value = 'Arbitrary data to hash';
    final hash = GenericHash.hashString(value);

    print(hex.encode(hash));
    // END generic1
  }

  void generic2(Function(Object) print) {
    // BEGIN generic2: Single-part with a key:
    final value = 'Arbitrary data to hash';
    final key = GenericHash.randomKey();

    final hash = GenericHash.hashString(value, key: key);

    print(hex.encode(hash));
    // END generic2
  }

  Future generic3(Function(Object) print) async {
    // BEGIN generic3: Multi-part without a key: Should result in a hash equal to the single-part without a key sample.
    final stream = Stream.fromIterable(['Arbitrary data ', 'to hash']);

    final hash = await GenericHash.hashStrings(stream);

    print(hex.encode(hash));
    // END generic3
  }

  Future generic4(Function(Object) print) async {
    // BEGIN generic4: Multi-part with a key:
    final stream = Stream.fromIterable(
        ['Arbitrary data to hash', 'is longer than expected']);
    final key = GenericHash.randomKey();

    final hash = await GenericHash.hashStrings(stream, key: key);

    print(hex.encode(hash));
    // END generic4
  }

  void pwhash1(Function(Object) print) {
    // BEGIN pwhash1: Hash: Derives a hash from given password and salt.
    final pw = 'hello world';
    final salt = PasswordHash.randomSalt();
    final hash = PasswordHash.hashString(pw, salt);

    print(hex.encode(hash));
    // END pwhash1
  }

  void pwhash2(Function(Object) print) {
    // BEGIN pwhash2: Hash storage: Computes a password verification string for given password.
    final pw = 'hello world';
    final str = PasswordHash.hashStringStorage(pw);
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
    final str = await compute(PasswordHash.hashStringStorageModerate, pw);

    print(str);
    print('Compute took ${watch.elapsedMilliseconds}ms');
    watch.stop();
    // END pwhash3
  }

  void shorthash1(Function(Object) print) {
    // BEGIN shorthash1: Usage: Computes a fixed-size fingerprint for given string value and key.
    final value = 'hello world';
    final key = ShortHash.randomKey();
    final hash = ShortHash.hashString(value, key);

    print(hex.encode(hash));
    // END shorthash1
  }
}
