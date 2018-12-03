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
        docUrl: 'https://libsodium.gitbook.io/doc/generating_random_data/',
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
    Example('Version',
        description: 'Provides libsodium version info.',
        docUrl: 'https://libsodium.gitbook.io/doc/',
        samples: [
          Sample(
              'Usage',
              'Retrieves the version of the loaded libsodium library',
              '''final version = await Sodium.sodiumVersionString();
print(version);''', () async {
            final version = await Sodium.sodiumVersionString();
            return version;
          })
        ]),
    Example('Secret-key cryptography', isHeader: true),
    Example('Authenticated encryption',
        description: 'Secret-key encryption and verification',
        docUrl:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption',
        samples: [
          Sample(
              'Combined mode',
              'The authentication tag and the encrypted message are stored together',
              '''// Generate random secret and nonce
var key = await SecretBox.generateKey();
var nonce = await SecretBox.generateNonce();

// Encrypt
var msg = 'hello world';
var encrypted = await SecretBox.encrypt(msg, nonce, key);

print(hex.encode(encrypted));

// Decrypt
var decrypted = await SecretBox.decrypt(encrypted, nonce, key);

assert(msg == decrypted);''', () async {
            // Generate random secret and nonce
            var key = await SecretBox.generateKey();
            var nonce = await SecretBox.generateNonce();

            // Encrypt
            var msg = 'hello world';
            var encrypted = await SecretBox.encrypt(msg, nonce, key);

            // Decrypt
            var decrypted = await SecretBox.decrypt(encrypted, nonce, key);

            assert(msg == decrypted);

            return hex.encode(encrypted);
          }),
          Sample(
              'Detached mode',
              'The authentication tag and the encrypted message are detached so they can be stored at different locations.',
              '''// Generate random secret and nonce
var key = await SecretBox.generateKey();
var nonce = await SecretBox.generateNonce();

// Encrypt
var msg = 'hello world';
var encrypted = await SecretBox.encryptDetached(msg, nonce, key);

print('cipher: \${encrypted.cipher}');
print('mac: \${encrypted.mac}');

// Decrypt
var decrypted =
    await SecretBox.decryptDetached(encrypted, nonce, key);

assert(msg == decrypted);''', () async {
            // Generate random secret and nonce
            var key = await SecretBox.generateKey();
            var nonce = await SecretBox.generateNonce();

            // Encrypt
            var msg = 'hello world';
            var encrypted = await SecretBox.encryptDetached(msg, nonce, key);

            // Decrypt
            var decrypted =
                await SecretBox.decryptDetached(encrypted, nonce, key);

            assert(msg == decrypted);

            return 'cipher: ${hex.encode(encrypted.cipher)}\nmac: ${hex.encode(encrypted.mac)}';
          })
        ]),
    Example('Authentication',
        description:
            'Computes an authentication tag for a message and a secret key, and provides a way to verify that a given tag is valid for a given message and a key.',
        docUrl:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/secret-key_authentication',
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
    Example('Original ChaCha20-Poly1305',
        description: 'Authenticated Encryption with Additional Data.',
        docUrl:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/original_chacha20-poly1305_construction',
        samples: [
          Sample(
              'Combined mode',
              'The authentication tag is directly appended to the encrypted message.',
              '''// Generate random nonce and key
var nonce = await ChaCha20Poly1305.generateNonce();
var key = await ChaCha20Poly1305.generateKey();

// Encrypt
var msg = 'hello world';
var data = '123456';
var ciphertext = await ChaCha20Poly1305.encrypt(msg, data, nonce, key);

print(hex.encode(ciphertext));

// Decrypt
var decrypted = await ChaCha20Poly1305.decrypt(ciphertext,data, nonce, key);

assert(msg == decrypted);''', () async {
            // Generate random nonce and key
            var nonce = await ChaCha20Poly1305.generateNonce();
            var key = await ChaCha20Poly1305.generateKey();

            // Encrypt
            var msg = 'hello world';
            var data = '123456';
            var ciphertext =
                await ChaCha20Poly1305.encrypt(msg, data, nonce, key);

            // Decrypt
            var decrypted =
                await ChaCha20Poly1305.decrypt(ciphertext, data, nonce, key);

            assert(msg == decrypted);

            return hex.encode(ciphertext);
          })
        ]),
    Example('IETF ChaCha20-Poly1305',
        description: 'Authenticated Encryption with Additional Data.',
        docUrl:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction',
        samples: [
          Sample(
              'Combined mode',
              'The authentication tag is directly appended to the encrypted message.',
              '''// Generate random nonce and key
var nonce = await ChaCha20Poly1305Ietf.generateNonce();
var key = await ChaCha20Poly1305Ietf.generateKey();

// Encrypt
var msg = 'hello world';
var data = '123456';
var ciphertext = await ChaCha20Poly1305Ietf.encrypt(msg, data, nonce, key);

print(hex.encode(ciphertext));

// Decrypt
var decrypted = await ChaCha20Poly1305Ietf.decrypt(ciphertext,data, nonce, key);

assert(msg == decrypted);''', () async {
            // Generate random nonce and key
            var nonce = await ChaCha20Poly1305Ietf.generateNonce();
            var key = await ChaCha20Poly1305Ietf.generateKey();

            // Encrypt
            var msg = 'hello world';
            var data = '123456';
            var ciphertext =
                await ChaCha20Poly1305Ietf.encrypt(msg, data, nonce, key);

            // Decrypt
            var decrypted = await ChaCha20Poly1305Ietf.decrypt(
                ciphertext, data, nonce, key);

            assert(msg == decrypted);

            return hex.encode(ciphertext);
          })
        ]),
    Example('XChaCha20-Poly1305',
        description: 'Authenticated Encryption with Additional Data.',
        docUrl:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction',
        samples: [
          Sample(
              'Combined mode',
              'The authentication tag is directly appended to the encrypted message.',
              '''// Generate random nonce and key
var nonce = await XChaCha20Poly1305Ietf.generateNonce();
var key = await XChaCha20Poly1305Ietf.generateKey();

// Encrypt
var msg = 'hello world';
var data = '123456';
var ciphertext = await XChaCha20Poly1305Ietf.encrypt(msg, data, nonce, key);

print(hex.encode(ciphertext));

// Decrypt
var decrypted = await XChaCha20Poly1305Ietf.decrypt(ciphertext,data, nonce, key);

assert(msg == decrypted);''', () async {
            // Generate random nonce and key
            var nonce = await XChaCha20Poly1305Ietf.generateNonce();
            var key = await XChaCha20Poly1305Ietf.generateKey();

            // Encrypt
            var msg = 'hello world';
            var data = '123456';
            var ciphertext =
                await XChaCha20Poly1305Ietf.encrypt(msg, data, nonce, key);

            // Decrypt
            var decrypted = await XChaCha20Poly1305Ietf.decrypt(
                ciphertext, data, nonce, key);

            assert(msg == decrypted);

            return hex.encode(ciphertext);
          }),
          Sample(
              'Detached mode',
              'Returns the encrypted message and authentication tag as seperate entities.',
              '''// Generate random nonce and key
var nonce = await XChaCha20Poly1305Ietf.generateNonce();
var key = await XChaCha20Poly1305Ietf.generateKey();

// Encrypt
var msg = 'hello world';
var data = '123456';
var encrypted = await XChaCha20Poly1305Ietf.encryptDetached(msg, data, nonce, key);

print('cipher: \${encrypted.cipher}');
print('mac: \${encrypted.mac}');

// Decrypt
var decrypted = await XChaCha20Poly1305Ietf.decryptDetached(encrypted, data, nonce, key);

assert(msg == decrypted);''', () async {
            // Generate random nonce and key
            var nonce = await XChaCha20Poly1305Ietf.generateNonce();
            var key = await XChaCha20Poly1305Ietf.generateKey();

            // Encrypt
            var msg = 'hello world';
            var data = '123456';
            var encrypted = await XChaCha20Poly1305Ietf.encryptDetached(
                msg, data, nonce, key);

            // Decrypt
            var decrypted = await XChaCha20Poly1305Ietf.decryptDetached(
                encrypted, data, nonce, key);

            assert(msg == decrypted);

            return 'cipher: ${hex.encode(encrypted.cipher)}\nmac: ${hex.encode(encrypted.mac)}';
          })
        ]),
    Example('Public-key cryptography', isHeader: true),
    Example('Authenticated encryption',
        description: 'Public-key authenticated encryption',
        docUrl:
            'https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption',
        samples: [
          Sample(
              'Combined mode',
              'The authentication tag and the encrypted message are stored together',
              '''// Generate key pairs
var alicePair = await CryptoBox.generateKeyPair();
var bobPair = await CryptoBox.generateKeyPair();

var nonce = await CryptoBox.generateNonce();

// Alice encrypts message for Bob
var msg = 'hello world';
var encrypted = await CryptoBox.encrypt(msg, nonce, bobPair.publicKey, alicePair.secretKey);

// Bob decrypts message from Alice
var decrypted = await CryptoBox.decrypt(encrypted, nonce, alicePair.publicKey, bobPair.secretKey);

assert(msg == decrypted);

print(hex.encode(encrypted));''', () async {
            // Generate key pairs
            var alicePair = await CryptoBox.generateKeyPair();
            var bobPair = await CryptoBox.generateKeyPair();

            var nonce = await CryptoBox.generateNonce();

            // Alice encrypts message for Bob
            var msg = 'hello world';
            var encrypted = await CryptoBox.encrypt(
                msg, nonce, bobPair.publicKey, alicePair.secretKey);

            // Bob decrypts message from Alice
            var decrypted = await CryptoBox.decrypt(
                encrypted, nonce, alicePair.publicKey, bobPair.secretKey);

            assert(msg == decrypted);

            return hex.encode(encrypted);
          }),
          Sample(
              'Detached mode',
              'The authentication tag and the encrypted message are detached so they can be stored at different locations.',
              '''// Generate key pairs
var alicePair = await CryptoBox.generateKeyPair();
var bobPair = await CryptoBox.generateKeyPair();

var nonce = await CryptoBox.generateNonce();

// Alice encrypts message for Bob
var msg = 'hello world';
var encrypted = await CryptoBox.encryptDetached(msg, nonce, bobPair.publicKey, alicePair.secretKey);

print('cipher: \${encrypted.cipher}');
print('mac: \${encrypted.mac}');

// Bob decrypts message from Alice
var decrypted = await CryptoBox.decryptDetached(encrypted, nonce, alicePair.publicKey, bobPair.secretKey);

assert(msg == decrypted);''', () async {
            // Generate key pairs
            var alicePair = await CryptoBox.generateKeyPair();
            var bobPair = await CryptoBox.generateKeyPair();

            var nonce = await CryptoBox.generateNonce();

            // Alice encrypts message for Bob
            var msg = 'hello world';
            var encrypted = await CryptoBox.encryptDetached(
                msg, nonce, bobPair.publicKey, alicePair.secretKey);

            // Bob decrypts message from Alice
            var decrypted = await CryptoBox.decryptDetached(
                encrypted, nonce, alicePair.publicKey, bobPair.secretKey);

            assert(msg == decrypted);

            return 'cipher: ${hex.encode(encrypted.cipher)}\nmac: ${hex.encode(encrypted.mac)}';
          })
        ]),
    Example('Public-key signatures',
        description:
            'Computes a signature for a message using a secret key, and provides verification using a public key.',
        docUrl:
            'https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures',
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
            'https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes',
        samples: [
          Sample(
              'Usage',
              'Anonymous sender encrypts a message intended for recipient only.',
              '''// Recipient creates a long-term key pair
var keyPair = await SealedBox.generateKeyPair();

// Anonymous sender encrypts a message using an ephemeral key pair and the recipient's public key
var msg = 'hello world';
var cipher = await SealedBox.seal(msg, keyPair.publicKey);

print(hex.encode(cipher));

// Recipient decrypts the ciphertext
var decrypted = await SealedBox.sealOpen(cipher, keyPair);

assert(msg == decrypted);''', () async {
            // Recipient creates a long-term key pair
            var keyPair = await SealedBox.generateKeyPair();

            // Anonymous sender encrypts a message using an ephemeral key pair and the recipient's public key
            var msg = 'hello world';
            var cipher = await SealedBox.seal(msg, keyPair.publicKey);

            // Recipient decrypts the ciphertext
            var decrypted = await SealedBox.sealOpen(cipher, keyPair);

            assert(msg == decrypted);

            return hex.encode(cipher);
          })
        ]),
    Example('Hashing', isHeader: true),
    Example('Generic hashing',
        description:
            'Computes a fixed-length fingerprint for an arbitrary long message using the BLAKE2b algorithm.',
        docUrl:
            'https://libsodium.gitbook.io/doc/hashing/generic_hashing',
        samples: [
          Sample(
              'Usage',
              'Computes a generic hash of specified length for given string value and optional key.',
              '''var value = 'hello world';
var hash = await GenericHash.hash(value);

print(hex.encode(hash));''', () async {
            var value = 'hello world';
            var hash = await GenericHash.hash(value);

            return hex.encode(hash);
          })
        ]),
    Example('Short-input hashing',
        description: 'Computes short hashes using the SipHash-2-4 algorithm.',
        docUrl:
            'https://libsodium.gitbook.io/doc/hashing/short-input_hashing',
        samples: [
          Sample(
              'Usage',
              'Computes a fixed-size fingerprint for given string value and key.',
              '''var value = 'hello world';
var key = await ShortHash.generateKey();
var hash = await ShortHash.hash(value, key);

print(hex.encode(hash));''', () async {
            var value = 'hello world';
            var key = await ShortHash.generateKey();
            var hash = await ShortHash.hash(value, key);

            return hex.encode(hash);
          })
        ]),
    Example('Password hashing',
        description:
            'Provides an Argon2 password hashing scheme implementation.',
        docUrl:
            'https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function',
        samples: [
          Sample('Hash', 'Derives a hash from given password and salt.',
              '''var pw = 'hello world';
var salt = await PasswordHash.generateSalt();
var hash = await PasswordHash.hash(pw, salt);

print(hex.encode(hash));''', () async {
            var pwd = 'hello world';
            var salt = await PasswordHash.generateSalt();
            var hash = await PasswordHash.hash(pwd, salt);
            return hex.encode(hash);
          }),
          Sample(
              'Hash storage',
              'Computes a password verification string for given password.',
              '''var pw = 'hello world';
var str = await PasswordHash.hashStorage(pw);

print(str);

// verify storage string
var valid = await PasswordHash.verifyStorage(str, pw);''', () async {
            var pwd = 'hello world';
            return await PasswordHash.hashStorage(pwd);
          })
        ]),
    Example('Key functions', isHeader: true),
    Example('Key derivation',
        description: 'Derive secret subkeys from a single master key.',
        docUrl: 'https://libsodium.gitbook.io/doc/key_derivation/',
        samples: [
          Sample('Usage', 'Compute a set of shared keys.',
              '''// Generate master key
final masterkey = await KeyDerivation.generateKey();

// Derives subkeys of various lengths
final subkey1 = await KeyDerivation.deriveFromKey(masterkey, 1, subKeyLength: 32);
final subkey2 = await KeyDerivation.deriveFromKey(masterkey, 2, subKeyLength: 32);
final subkey3 = await KeyDerivation.deriveFromKey(masterkey, 3, subKeyLength: 64);

print('subkey1: \${hex.encode(subkey1)}')
print('subkey2: \${hex.encode(subkey2)}')
print('subkey3: \${hex.encode(subkey3)}');''', () async {
            // Generate master key
            final masterkey = await KeyDerivation.generateKey();

            // Derives subkeys of various lengths
            final subkey1 = await KeyDerivation.deriveFromKey(masterkey, 1,
                subKeyLength: 32);
            final subkey2 = await KeyDerivation.deriveFromKey(masterkey, 2,
                subKeyLength: 32);
            final subkey3 = await KeyDerivation.deriveFromKey(masterkey, 3,
                subKeyLength: 64);

            return 'subkey1: ${hex.encode(subkey1)}\nsubkey2: ${hex.encode(subkey2)}\nsubkey3: ${hex.encode(subkey3)}\n';
          })
        ]),
    Example('Key exchange',
        description: 'Securely compute a set of shared keys.',
        docUrl: 'https://libsodium.gitbook.io/doc/key_exchange/',
        samples: [
          Sample(
              'Usage', 'Compute a set of shared keys.', '''// Generate key pairs
final clientPair = await KeyExchange.generateKeyPair();
final serverPair = await KeyExchange.generateKeyPair();

// Compute session keys
final clientKeys = await KeyExchange.computeClientSessionKeys(clientPair, serverPair.publicKey);
final serverKeys = await KeyExchange.computeServerSessionKeys(serverPair, clientPair.publicKey);

// assert keys do match
assert(
    const ListEquality().equals(clientKeys.rx, serverKeys.tx));
assert(
    const ListEquality().equals(clientKeys.tx, serverKeys.rx));
    
print('client rx: \${hex.encode(clientKeys.rx)}')
print('client tx: \${hex.encode(clientKeys.tx)}');''', () async {
            // Generate key pairs
            final clientPair = await KeyExchange.generateKeyPair();
            final serverPair = await KeyExchange.generateKeyPair();

            // Compute session keys
            final clientKeys = await KeyExchange.computeClientSessionKeys(
                clientPair, serverPair.publicKey);
            final serverKeys = await KeyExchange.computeServerSessionKeys(
                serverPair, clientPair.publicKey);

            // assert keys do match
            assert(const ListEquality().equals(clientKeys.rx, serverKeys.tx));
            assert(const ListEquality().equals(clientKeys.tx, serverKeys.rx));

            return 'client rx: ${hex.encode(clientKeys.rx)}\nclient tx: ${hex.encode(clientKeys.tx)}';
          })
        ]),
    Example('Advanced', isHeader: true),
    Example('Diffie-Hellman',
        description: 'Perform scalar multiplication of elliptic curve points',
        docUrl:
            'https://libsodium.gitbook.io/doc/advanced/scalar_multiplication',
        samples: [
          Sample('Usage', 'Computes a shared secret.',
              '''// Create client's secret and public keys
final clientSecretKey = await ScalarMult.generateSecretKey();
final clientPublicKey =
    await ScalarMult.computePublicKey(clientSecretKey);

// Create server's secret and public keys
final serverSecretKey = await ScalarMult.generateSecretKey();
final serverPublicKey =
    await ScalarMult.computePublicKey(serverSecretKey);

// Client derives shared key and hashes it
final clientQ = await ScalarMult.computeSharedSecret(
    clientSecretKey, serverPublicKey);
final sharedKeyClient = await GenericHash.hashByteStream(
    Stream
        .fromIterable([clientQ, clientPublicKey, serverPublicKey]));

// Server derives shared key and hashes it
final serverQ = await ScalarMult.computeSharedSecret(
    serverSecretKey, clientPublicKey);
final sharedKeyServer = await GenericHash.hashByteStream(
    Stream
        .fromIterable([serverQ, clientPublicKey, serverPublicKey]));

// assert shared keys do match
assert(
    const ListEquality().equals(sharedKeyClient, sharedKeyServer));

print(hex.encode(sharedKeyClient));
''', () async {
            // Create client's secret and public keys
            final clientSecretKey = await ScalarMult.generateSecretKey();
            final clientPublicKey =
                await ScalarMult.computePublicKey(clientSecretKey);

            // Create server's secret and public keys
            final serverSecretKey = await ScalarMult.generateSecretKey();
            final serverPublicKey =
                await ScalarMult.computePublicKey(serverSecretKey);

            // Client derives shared key and hashes it
            final clientQ = await ScalarMult.computeSharedSecret(
                clientSecretKey, serverPublicKey);
            final sharedKeyClient = await GenericHash.hashByteStream(Stream
                .fromIterable([clientQ, clientPublicKey, serverPublicKey]));

            // Server derives shared key and hashes it
            final serverQ = await ScalarMult.computeSharedSecret(
                serverSecretKey, clientPublicKey);
            final sharedKeyServer = await GenericHash.hashByteStream(Stream
                .fromIterable([serverQ, clientPublicKey, serverPublicKey]));

            // assert shared keys do match
            assert(
                const ListEquality().equals(sharedKeyClient, sharedKeyServer));

            return hex.encode(sharedKeyClient);
          })
        ]),
    Example('One-time authentication',
        description: 'Secret-key single-message authentication using Poly1305',
        docUrl: 'https://libsodium.gitbook.io/doc/advanced/poly1305',
        samples: [
          Sample(
              'Usage',
              'Computes and verifies a tag for given string value and key.',
              '''var message = 'hello world';
var key = await OnetimeAuth.generateKey();
var tag = await OnetimeAuth.compute(message, key);

print(hex.encode(tag));

// verify tag
var valid = await OnetimeAuth.verify(tag, message, key);
assert(valid);
''', () async {
            var message = 'hello world';
            var key = await OnetimeAuth.generateKey();
            var tag = await OnetimeAuth.compute(message, key);

// verify tag
            var valid = await OnetimeAuth.verify(tag, message, key);
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
        body: SafeArea(
            child: ListView(
                children: _examples
                    .map((e) => _buildListTile(context, e))
                    .toList())));
  }
}
