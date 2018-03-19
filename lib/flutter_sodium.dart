import 'dart:async';
import 'dart:typed_data';
import 'package:flutter/services.dart';
export 'src/constants.dart';

/// Sodium is a modern, easy-to-use software library for encryption, decryption, signatures, password hashing and more.
class Sodium {
  static const MethodChannel _channel = const MethodChannel('flutter_sodium');

  //
  // crypto_auth
  //
  /// Computes a tag for specified input and key.
  static Future<Uint8List> cryptoAuth(Uint8List i, Uint8List k) =>
      _channel.invokeMethod('crypto_auth', {'in': i, 'k': k});

  /// Verifies that the tag stored at h is a valid tag for the input and key.
  static Future<bool> cryptoAuthVerify(Uint8List h, Uint8List i, Uint8List k) =>
      _channel.invokeMethod('crypto_auth_verify', {'h': h, 'in': i, 'k': k});

  /// Generates a random key.
  static Future<Uint8List> cryptoAuthKeygen() =>
      _channel.invokeMethod('crypto_auth_keygen');

  //
  // crypto_box
  //
  /// Deterministically derive a key pair from a single key seed.
  static Future<Map<String, Uint8List>> cryptoBoxSeedKeypair(Uint8List seed) =>
      _channel.invokeMethod('crypto_box_seed_keypair', {'seed': seed});

  /// Generates a random secret key and a corresponding public key.
  static Future<Map<String, Uint8List>> cryptoBoxKeypair() =>
      _channel.invokeMethod('crypto_box_keypair');

  /// Encrypts a message with a recipient's public key, a sender's secret key and a nonce.
  static Future<Uint8List> cryptoBoxEasy(
          Uint8List m, Uint8List n, Uint8List pk, Uint8List sk) =>
      _channel.invokeMethod(
          'crypto_box_easy', {'m': m, 'n': n, 'pk': pk, 'sk': sk});

  /// Verifies and decrypts a ciphertext produced by [cryptoBoxEasy].
  static Future<Uint8List> cryptoBoxOpenEasy(
          Uint8List c, Uint8List n, Uint8List pk, Uint8List sk) =>
      _channel.invokeMethod(
          'crypto_box_open_easy', {'c': c, 'n': n, 'pk': pk, 'sk': sk});

  /// Encrypts a message with a recipient's public key, a sender's secret key and a nonce. Returns the encrypted message and mac.
  static Future<Map<String, Uint8List>> cryptoBoxDetached(
          Uint8List m, Uint8List n, Uint8List pk, Uint8List sk) =>
      _channel.invokeMethod(
          'crypto_box_detached', {'m': m, 'n': n, 'pk': pk, 'sk': sk});

  /// Verifies and decrypts a ciphertext produced by [cryptoBoxDetached].
  static Future<Uint8List> cryptoBoxOpenDetached(Uint8List c, Uint8List mac,
          Uint8List n, Uint8List pk, Uint8List sk) =>
      _channel.invokeMethod('crypto_box_open_detached',
          {'c': c, 'mac': mac, 'n': n, 'pk': pk, 'sk': sk});

  /// Computes a shared secret key given a public key and a secret key.
  static Future<Uint8List> cryptoBoxBeforenm(Uint8List pk, Uint8List sk) =>
      _channel.invokeMethod('crypto_box_beforenm', {'pk': pk, 'sk': sk});

  /// Encrypts a message with a shared secret key and a nonce.
  static Future<Uint8List> cryptoBoxEasyAfternm(
          Uint8List m, Uint8List n, Uint8List k) =>
      _channel
          .invokeMethod('crypto_box_easy_afternm', {'m': m, 'n': n, 'k': k});

  /// Verifies and decrypts a ciphertext with a shared secret key and a nonce.
  static Future<Uint8List> cryptoBoxOpenEasyAfternm(
          Uint8List c, Uint8List n, Uint8List k) =>
      _channel.invokeMethod(
          'crypto_box_open_easy_afternm', {'c': c, 'n': n, 'k': k});

  /// Encrypts a message with a shared secret key and a nonce. Returns the encrypted message and mac.
  static Future<Map<String, Uint8List>> cryptoBoxDetachedAfternm(
          Uint8List m, Uint8List n, Uint8List k) =>
      _channel.invokeMethod(
          'crypto_box_detached_afternm', {'m': m, 'n': n, 'k': k});

  /// Verifies and decrypts a ciphertext with a mac, a shared secret key and a nonce.
  static Future<Uint8List> cryptoBoxOpenDetachedAfternm(
          Uint8List c, Uint8List mac, Uint8List n, Uint8List k) =>
      _channel.invokeMethod('crypto_box_open_detached_afternm',
          {'c': c, 'mac': mac, 'n': n, 'k': k});

  //
  // crypto_box_seal
  //
  /// Encrypts a message for a recipient whose public key is pk
  static Future<Uint8List> cryptoBoxSeal(Uint8List m, Uint8List pk) =>
      _channel.invokeMethod('crypto_box_seal', {'m': m, 'pk': pk});

  /// Decrypts the ciphertext using specified key pair.
  static Future<Uint8List> cryptoBoxSealOpen(
          Uint8List c, Uint8List pk, Uint8List sk) =>
      _channel
          .invokeMethod('crypto_box_seal_open', {'c': c, 'pk': pk, 'sk': sk});

  //
  // crypto_generichash
  //
  /// Computes a fingerprint of specified length for given input and key.
  static Future<Uint8List> cryptoGenerichash(
          int outlen, Uint8List i, Uint8List key) =>
      _channel.invokeMethod(
          'crypto_generichash', {'outlen': outlen, 'in': i, 'key': key});

  /// Initializes the hash state for the streaming API.
  static Future<Uint8List> cryptoGenerichashInit(Uint8List key, int outlen) =>
      _channel.invokeMethod(
          'crypto_generichash_init', {'key': key, 'outlen': outlen});

  /// Computes the hash for a part of a message.
  static Future<Uint8List> cryptoGenerichashUpdate(
          Uint8List state, Uint8List i) =>
      _channel
          .invokeMethod('crypto_generichash_update', {'state': state, 'in': i});

  /// Completes the hash computation and returns the hash.
  static Future<Uint8List> cryptoGenerichashFinal(
          Uint8List state, int outlen) =>
      _channel.invokeMethod(
          'crypto_generichash_final', {'state': state, 'outlen': outlen});

  /// Generates a random key for generic hashing.
  static Future<Uint8List> cryptoGenerichashKeygen() =>
      _channel.invokeMethod('crypto_generichash_keygen');

  //
  // crypto_kdf
  //
  /// Creates a master key.
  static Future<Uint8List> cryptoKdfKeygen() =>
      _channel.invokeMethod('crypto_kdf_keygen');

  /// Derives a subkey using a master key and a context.
  static Future<Uint8List> cryptoKdfDeriveFromKey(
          int subkeyLen, int subkeyId, Uint8List ctx, Uint8List key) =>
      _channel.invokeMethod('crypto_kdf_derive_from_key', {
        'subkey_len': subkeyLen,
        'subkey_id': subkeyId,
        'ctx': ctx,
        'key': key
      });

  //
  // crypto_kx
  //
  /// Creates a new key pair.
  static Future<Map<String, Uint8List>> cryptoKxKeypair() =>
      _channel.invokeMethod('crypto_kx_keypair');

  /// Computes a deterministic key pair from the seed.
  static Future<Map<String, Uint8List>> cryptoKxSeedKeypair(Uint8List seed) =>
      _channel.invokeMethod('crypto_kx_seed_keypair', {'seed': seed});

  /// Computes a pair of shared keys (rx and tx) using the client's public key, the client's secret key and the server's public key.
  static Future<Map<String, Uint8List>> cryptoKxClientSessionKeys(
          Uint8List clientPk, Uint8List clientSk, Uint8List serverPk) =>
      _channel.invokeMethod('crypto_kx_client_session_keys', {
        'client_pk': clientPk,
        'client_sk': clientSk,
        'server_pk': serverPk
      });

  /// Computes a pair of shared keys (rx and tx) using the server's public key, the server's secret key and the client's public key.
  static Future<Map<String, Uint8List>> cryptoKxServerSessionKeys(
          Uint8List serverPk, Uint8List serverSk, Uint8List clientPk) =>
      _channel.invokeMethod('crypto_kx_server_session_keys', {
        'server_pk': serverPk,
        'server_sk': serverSk,
        'client_pk': clientPk
      });

  //
  // crypto_onetimeauth
  //
  /// Authenticates a message using a secret key.
  static Future<Uint8List> cryptoOnetimeauth(Uint8List i, Uint8List k) =>
      _channel.invokeMethod('crypto_onetimeauth', {'in': i, 'k': k});

  /// Verifies that h is a correct authenticator for the message using given secret key.
  static Future<bool> cryptoOnetimeauthVerify(
          Uint8List h, Uint8List i, Uint8List k) =>
      _channel
          .invokeMethod('crypto_onetimeauth_verify', {'h': h, 'in': i, 'k': k});

  /// Initializes the authentication state for the streaming API.
  static Future<Uint8List> cryptoOnetimeauthInit(Uint8List key) =>
      _channel.invokeMethod('crypto_onetimeauth_init', {'key': key});

  /// Computes the authenticator from sequential chunks of the message.
  static Future<Uint8List> cryptoOnetimeauthUpdate(
          Uint8List state, Uint8List i) =>
      _channel
          .invokeMethod('crypto_onetimeauth_update', {'state': state, 'in': i});

  /// Completes the computation and returns the authenticator.
  static Future<Uint8List> cryptoOnetimeauthFinal(Uint8List state) =>
      _channel.invokeMethod('crypto_onetimeauth_final', {'state': state});

  /// Generates a random key for use in onetime authentication.
  static Future<Uint8List> cryptoOnetimeauthKeygen() =>
      _channel.invokeMethod('crypto_onetimeauth_keygen');

  //
  // crypto_pwhash
  //
  /// Derives a key from a password and a salt.
  static Future<Uint8List> cryptoPwhash(int outlen, Uint8List passwd,
          Uint8List salt, int opslimit, int memlimit, int alg) =>
      _channel.invokeMethod('crypto_pwhash', {
        'outlen': outlen,
        'passwd': passwd,
        'salt': salt,
        'opslimit': opslimit,
        'memlimit': memlimit,
        'alg': alg
      });

  /// Derives an ASCII encoded string containing a hash, automatically generated salt, and other parameters required to verify the password.
  static Future<Uint8List> cryptoPwhashStr(
          Uint8List passwd, int opslimit, int memlimit) =>
      _channel.invokeMethod('crypto_pwhash_str', {
        'passwd': passwd,
        'opslimit': opslimit,
        'memlimit': memlimit,
      });

  /// Verifies that str is a valid password verification string.
  static Future<bool> cryptoPwhashStrVerify(Uint8List str, Uint8List passwd) =>
      _channel.invokeMethod(
          'crypto_pwhash_str_verify', {'str': str, 'passwd': passwd});

  /// Check if a password verification string matches the parameters opslimit and memlimit, and the current default algorithm.
  static Future<bool> cryptoPwhashStrNeedsRehash(
          Uint8List str, int opslimit, int memlimit) =>
      _channel.invokeMethod('crypto_pwhash_str_needs_rehash',
          {'str': str, 'opslimit': opslimit, 'memlimit': memlimit});

  //
  // crypto_secretbox
  //
  /// Encrypts a message with a key and a nonce.
  static Future<Uint8List> cryptoSecretboxEasy(
          Uint8List m, Uint8List n, Uint8List k) =>
      _channel.invokeMethod('crypto_secretbox_easy', {'m': m, 'n': n, 'k': k});

  /// Verifies and decrypts a ciphertext produced by [cryptoSecretboxEasy].
  static Future<Uint8List> cryptoSecretboxOpenEasy(
          Uint8List c, Uint8List n, Uint8List k) =>
      _channel
          .invokeMethod('crypto_secretbox_open_easy', {'c': c, 'n': n, 'k': k});

  /// Encrypts a message with a key and a nonce, and returns the encrypted message and mac.
  static Future<Map<String, Uint8List>> cryptoSecretboxDetached(
          Uint8List m, Uint8List n, Uint8List k) =>
      _channel
          .invokeMethod('crypto_secretbox_detached', {'m': m, 'n': n, 'k': k});

  /// Verifies and decrypts an encrypted message.
  static Future<Uint8List> cryptoSecretboxOpenDetached(
          Uint8List c, Uint8List mac, Uint8List n, Uint8List k) =>
      _channel.invokeMethod('crypto_secretbox_open_detached',
          {'c': c, 'mac': mac, 'n': n, 'k': k});

  /// Creates a random key
  static Future<Uint8List> cryptoSecretboxKeygen() =>
      _channel.invokeMethod('crypto_secretbox_keygen');

  //
  // crypto_scalarmult
  //
  /// Computes a public key given specified secret key.
  static Future<Uint8List> cryptoScalarmultBase(Uint8List n) =>
      _channel.invokeMethod('crypto_scalarmult_base', {'n': n});

  /// Computes a shared secret given a user's secret key and another user's public key.
  static Future<Uint8List> cryptoScalarmult(Uint8List n, Uint8List p) =>
      _channel.invokeMethod('crypto_scalarmult', {'n': n, 'p': p});

  //
  // crypto_shorthash
  //
  /// Computes a fixed-size fingerprint for specified input and key.
  static Future<Uint8List> cryptoShorthash(Uint8List i, Uint8List k) =>
      _channel.invokeMethod('crypto_shorthash', {'in': i, 'k': k});

  /// Generates a random key.
  static Future<Uint8List> cryptoShorthashKeygen() =>
      _channel.invokeMethod('crypto_shorthash_keygen');

  //
  // randombytes
  //
  /// Returns an unpredictable sequence of bytes of size [size].
  static Future<Uint8List> randombytesBuf(int size) =>
      _channel.invokeMethod('randombytes_buf', {'size': size});

  /// Returns an unpredictable sequence of bytes of size [size] using given [seed].
  ///
  /// For a given seed, this function will always output the same sequence
  static Future<Uint8List> randombytesBufDeterministic(
          int size, Uint8List seed) =>
      _channel.invokeMethod(
          'randombytes_buf_deterministic', {'size': size, 'seed': seed});

  /// Returns an unpredictable value between 0 and 0xffffffff (included).
  static Future<int> randombytesRandom() =>
      _channel.invokeMethod('randombytes_random');

  /// Returns an unpredictable value between 0 and upper_bound (excluded).
  ///
  /// It guarantees a uniform distribution of the possible output values even when [upperBound] is not a power of 2.
  static Future<int> randombytesUniform(int upperBound) =>
      _channel.invokeMethod('randombytes_uniform', {'upper_bound': upperBound});

  /// Reseeds the pseudo-random number generator.
  static Future<int> randombytesStir() =>
      _channel.invokeMethod('randombytes_stir');

  /// Deallocates the global resources used by the pseudo-random number generator.
  ///
  /// Explicitly calling this function is almost never required.
  static Future<int> randombytesClose() =>
      _channel.invokeMethod('randombytes_close');

  //
  // sodium_version
  //
  static Future<String> sodiumVersionString() =>
      _channel.invokeMethod('sodium_version_string');
}
