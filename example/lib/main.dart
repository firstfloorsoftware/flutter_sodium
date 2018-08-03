import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'example.dart';
import 'sample.dart';

void main() => runApp(new MyApp());

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(home: HomePage());
  }
}

class HomePage extends StatelessWidget {
  final _examples = [
    Example('Common', isHeader: true),
    Example('Random data',
        description:
            'Provides a set of functions to generate unpredictable data, suitable for creating secret keys.',
        docUrl: 'https://download.libsodium.org/doc/generating_random_data/',
        samples: [
          Sample(
              'Random',
              'Returns an unpredictable value between 0 and 0xffffffff (included)',
              '''final rnd = await RandomBytes.random();
print(rnd);''', () async {
            final rnd = await RandomBytes.random();
            return rnd.toString();
          }),
          Sample(
              'Uniform',
              'Generates an unpredictable value between 0 and upperBound (excluded)',
              '''final rnd = await RandomBytes.uniform(16);
print(rnd);''', () async {
            final rnd = await RandomBytes.uniform(16);
            return rnd.toString();
          }),
          Sample(
              'Buffer',
              'Generates an unpredictable sequence of bytes of specified size.',
              '''final buffer = await RandomBytes.buffer(16);
print(hex.encode(buffer));''', () async {
            final buffer = await RandomBytes.buffer(16);
            return hex.encode(buffer);
          })
        ]),
    Example('Secret-key cryptography', isHeader: true),
    Example('Authenticated encryption',
        description: 'Secret-key encryption and verification',
        docUrl:
            'https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html',
        samples: [
          Sample(
              'Combined mode',
              'The authentication tag and the encrypted message are stored together',
              '''// Generate random secret and nonce
var key = await CryptoSecretBox.generateKey();
var nonce = await CryptoSecretBox.generateNonce();

// Encrypt
var msg = 'hello world';
var encrypted = await CryptoSecretBox.encrypt(msg, nonce, key);

print(hex.encode(encrypted));

// Decrypt
var decrypted = await CryptoSecretBox.decrypt(encrypted, nonce, key);

assert(msg == decrypted);''', () async {
            // Generate random secret and nonce
            var key = await CryptoSecretBox.generateKey();
            var nonce = await CryptoSecretBox.generateNonce();

            // Encrypt
            var msg = 'hello world';
            var encrypted = await CryptoSecretBox.encrypt(msg, nonce, key);

            // Decrypt
            var decrypted =
                await CryptoSecretBox.decrypt(encrypted, nonce, key);

            assert(msg == decrypted);

            return hex.encode(encrypted);
          }),
          Sample(
              'Detached mode',
              'The authentication tag and the encrypted message are detached so they can be stored at different locations.',
              '''// Generate random secret and nonce
var key = await CryptoSecretBox.generateKey();
var nonce = await CryptoSecretBox.generateNonce();

// Encrypt
var msg = 'hello world';
var encrypted = await CryptoSecretBox.encryptDetached(msg, nonce, key);

print('cipher: \${encrypted.cipher}');
print('mac: \${encrypted.mac}');

// Decrypt
var decrypted =
    await CryptoSecretBox.decryptDetached(encrypted, nonce, key);

assert(msg == decrypted);''', () async {
            // Generate random secret and nonce
            var key = await CryptoSecretBox.generateKey();
            var nonce = await CryptoSecretBox.generateNonce();

            // Encrypt
            var msg = 'hello world';
            var encrypted =
                await CryptoSecretBox.encryptDetached(msg, nonce, key);

            // Decrypt
            var decrypted =
                await CryptoSecretBox.decryptDetached(encrypted, nonce, key);

            assert(msg == decrypted);

            return 'cipher: ${hex.encode(encrypted.cipher)}\nmac: ${hex.encode(encrypted.mac)}';
          })
        ]),
    Example('Authentication',
        description:
            'Computes an authentication tag for a message and a secret key, and provides a way to verify that a given tag is valid for a given message and a key.',
        docUrl:
            'https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html',
        samples: [
          Sample('Usage', 'Secret key authentication.', '''// Generate secret
var key = await CryptoAuth.generateKey();

// Compute tag
var msg = 'hello world';
var tag = await CryptoAuth.compute(msg, key);

print(hex.encode(tag));

// Verify tag
var valid = await CryptoAuth.verify(tag, msg, key);

assert(valid);''', () async {
            // Generate secret
            var key = await CryptoAuth.generateKey();

            // Compute tag
            var msg = 'hello world';
            var tag = await CryptoAuth.compute(msg, key);

            // Verify tag
            var valid = await CryptoAuth.verify(tag, msg, key);

            assert(valid);

            return hex.encode(tag);
          })
        ]),
    Example('Public-key cryptography', isHeader: true),
    // Example('Authenticated encryption'),
    Example('Public-key signatures',
        description:
            'Computes a signature for a message using a secret key, and provides verification using a public key.',
        docUrl:
            'https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html',
        samples: [
          Sample('Usage', 'Public key verification (detached mode).',
              '''// Author generates keypair
var keyPair = await CryptoSign.generateKeyPair();

// Author computes signature using secret key
var msg = 'hello world';
var sig = await CryptoSign.sign(msg, keyPair.secretKey);

print(hex.encode(sig));

// Recipient verifies message was issued by author using public key
var valid = await CryptoSign.verify(sig, msg, keyPair.publicKey);

assert(valid);''', () async {
            // Author generates keypair
            var keyPair = await CryptoSign.generateKeyPair();

            // Author computes signature using secret key
            var msg = 'hello world';
            var sig = await CryptoSign.sign(msg, keyPair.secretKey);

            // Recipient verifies message was issued by author using public key
            var valid = await CryptoSign.verify(sig, msg, keyPair.publicKey);

            assert(valid);

            return hex.encode(sig);
          })
        ]),
    Example('Sealed boxes',
        description:
            'Anonymously send encrypted messages to a recipient given its public key.',
        docUrl:
            'https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html',
        samples: [
          Sample(
              'Usage',
              'Anonymous sender encrypts a message intended for recipient only.',
              '''// Recipient creates a long-term key pair
var keyPair = await CryptoBox.generateKeyPair();

// Anonymous sender encrypts a message using an ephemeral key pair and the recipient's public key
var msg = 'hello world';
var cipher = await CryptoBox.seal(msg, keyPair.publicKey);

print(hex.encode(cipher));

// Recipient decrypts the ciphertext
var decrypted = await CryptoBox.sealOpen(cipher, keyPair);

assert(msg == decrypted);''', () async {
            // Recipient creates a long-term key pair
            var keyPair = await CryptoBox.generateKeyPair();

            // Anonymous sender encrypts a message using an ephemeral key pair and the recipient's public key
            var msg = 'hello world';
            var cipher = await CryptoBox.seal(msg, keyPair.publicKey);

            // Recipient decrypts the ciphertext
            var decrypted = await CryptoBox.sealOpen(cipher, keyPair);

            assert(msg == decrypted);

            return hex.encode(cipher);
          })
        ]),

    Example('Hashing', isHeader: true),
    Example('Generic hashing',
        description:
            'Computes a fixed-length fingerprint for an arbitrary long message using the BLAKE2b algorithm.',
        docUrl:
            'https://download.libsodium.org/doc/hashing/generic_hashing.html',
        samples: [
          Sample(
              'Usage',
              'Computes a generic hash of specified length for given string value and optional key.',
              '''var value = 'hello world';
var hash = await CryptoGenericHash.hash(value);

print(hex.encode(hash));''', () async {
            var value = 'hello world';
            var hash = await CryptoGenericHash.hash(value);

            return hex.encode(hash);
          })
        ]),
    Example('Short-input hashing',
        description: 'Computes short hashes using the SipHash-2-4 algorithm.',
        docUrl:
            'https://download.libsodium.org/doc/hashing/short-input_hashing.html',
        samples: [
          Sample(
              'Usage',
              'Computes a fixed-size fingerprint for given string value and key.',
              '''var value = 'hello world';
var key = await CryptoShortHash.generateKey();
var hash = await CryptoShortHash.hash(value, key);

print(hex.encode(hash));''', () async {
            var value = 'hello world';
            var key = await CryptoShortHash.generateKey();
            var hash = await CryptoShortHash.hash(value, key);

            return hex.encode(hash);
          })
        ]),
    Example('Password hashing',
        description:
            'Provides an Argon2 password hashing scheme implementation.',
        docUrl:
            'https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html',
        samples: [
          Sample('Hash', 'Derives a hash from given password and salt.',
              '''var pw = 'hello world';
var salt = await CryptoPasswordHash.generateSalt();
var hash = await CryptoPasswordHash.hash(pw, salt);

print(hex.encode(hash));''', () async {
            var pwd = 'hello world';
            var salt = await CryptoPasswordHash.generateSalt();
            var hash = await CryptoPasswordHash.hash(pwd, salt);
            return hex.encode(hash);
          }),
          Sample(
              'Hash storage',
              'Computes a password verification string for given password.',
              '''var pw = 'hello world';
var str = await CryptoPasswordHash.hashStorage(pw);

print(str);

// verify storage string
var valid = await CryptoPasswordHash.verifyStorage(str, pw);''', () async {
            var pwd = 'hello world';
            return await CryptoPasswordHash.hashStorage(pwd);
          })
        ]),
    // Example('Key functions', isHeader: true),
    // Example('Key derivation'),
    // Example('Key exchange'),
    Example('Advanced', isHeader: true),
    Example('Diffie-Hellman',
        description: 'Perform scalar multiplication of elliptic curve points',
        docUrl:
            'https://download.libsodium.org/doc/advanced/scalar_multiplication.html',
        samples: [
          Sample('Usage', 'Computes a shared secret.',
              '''// Create client's secret and public keys
final clientSecretKey = await CryptoScalarMult.generateSecretKey();
final clientPublicKey =
    await CryptoScalarMult.computePublicKey(clientSecretKey);

// Create server's secret and public keys
final serverSecretKey = await CryptoScalarMult.generateSecretKey();
final serverPublicKey =
    await CryptoScalarMult.computePublicKey(serverSecretKey);

// Client derives shared key and hashes it
final clientQ = await CryptoScalarMult.computeSharedSecret(
    clientSecretKey, serverPublicKey);
final sharedKeyClient = await CryptoGenericHash.hashByteStream(
    Stream
        .fromIterable([clientQ, clientPublicKey, serverPublicKey]));

// Server derives shared key and hashes it
final serverQ = await CryptoScalarMult.computeSharedSecret(
    serverSecretKey, clientPublicKey);
final sharedKeyServer = await CryptoGenericHash.hashByteStream(
    Stream
        .fromIterable([serverQ, clientPublicKey, serverPublicKey]));

// assert shared keys do match
assert(
    const ListEquality().equals(sharedKeyClient, sharedKeyServer));

print(hex.encode(sharedKeyClient));
''', () async {
            // Create client's secret and public keys
            final clientSecretKey = await CryptoScalarMult.generateSecretKey();
            final clientPublicKey =
                await CryptoScalarMult.computePublicKey(clientSecretKey);

            // Create server's secret and public keys
            final serverSecretKey = await CryptoScalarMult.generateSecretKey();
            final serverPublicKey =
                await CryptoScalarMult.computePublicKey(serverSecretKey);

            // Client derives shared key and hashes it
            final clientQ = await CryptoScalarMult.computeSharedSecret(
                clientSecretKey, serverPublicKey);
            final sharedKeyClient = await CryptoGenericHash.hashByteStream(
                Stream
                    .fromIterable([clientQ, clientPublicKey, serverPublicKey]));

            // Server derives shared key and hashes it
            final serverQ = await CryptoScalarMult.computeSharedSecret(
                serverSecretKey, clientPublicKey);
            final sharedKeyServer = await CryptoGenericHash.hashByteStream(
                Stream
                    .fromIterable([serverQ, clientPublicKey, serverPublicKey]));

            // assert shared keys do match
            assert(
                const ListEquality().equals(sharedKeyClient, sharedKeyServer));

            return hex.encode(sharedKeyClient);
          })
        ]),
    Example('One-time authentication',
        description: 'Secret-key single-message authentication using Poly1305',
        docUrl: 'https://download.libsodium.org/doc/advanced/poly1305.html',
        samples: [
          Sample(
              'Usage',
              'Computes and verifies a tag for given string value and key.',
              '''var message = 'hello world';
var key = await CryptoOnetimeAuth.generateKey();
var tag = await CryptoOnetimeAuth.compute(message, key);

print(hex.encode(tag));

// verify tag
var valid = await CryptoOnetimeAuth.verify(tag, message, key);
assert(valid);
''', () async {
            var message = 'hello world';
            var key = await CryptoOnetimeAuth.generateKey();
            var tag = await CryptoOnetimeAuth.compute(message, key);

// verify tag
            var valid = await CryptoOnetimeAuth.verify(tag, message, key);
            assert(valid);

            return hex.encode(tag);
          })
        ]),
  ];

  Widget _buildListTile(BuildContext context, Example example) {
    if (example.isHeader) {
      return ListTile(
          title: Text(example.title, style: Theme.of(context).textTheme.title));
    } else {
      return ListTile(
          title: Text(example.title),
          trailing: Icon(Icons.arrow_forward_ios, size: 12.0),
          onTap: () => example.navigate(context));
    }
  }

  @override
  Widget build(BuildContext context) {
    return new Scaffold(
        appBar: new AppBar(
          title: new Text("Flutter Sodium"),
        ),
        body: ListView(
            children:
                _examples.map((e) => _buildListTile(context, e)).toList()));
  }
}
