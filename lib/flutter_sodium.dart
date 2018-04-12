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
  static Future<Uint8List> cryptoAuth(Uint8List i, Uint8List k) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_auth', {'in': i, 'k': k});
    return result;
  }

  /// Verifies that the tag stored at h is a valid tag for the input and key.
  static Future<bool> cryptoAuthVerify(
      Uint8List h, Uint8List i, Uint8List k) async {
    final bool result = await _channel
        .invokeMethod('crypto_auth_verify', {'h': h, 'in': i, 'k': k});
    return result;
  }

  /// Generates a random key.
  static Future<Uint8List> cryptoAuthKeygen() async {
    final Uint8List result = await _channel.invokeMethod('crypto_auth_keygen');
    return result;
  }

  //
  // crypto_box
  //
  /// Deterministically derive a key pair from a single key seed.
  static Future<Map<String, Uint8List>> cryptoBoxSeedKeypair(
      Uint8List seed) async {
    final Map result =
        await _channel.invokeMethod('crypto_box_seed_keypair', {'seed': seed});
    return result.retype<String, Uint8List>();
  }

  /// Generates a random secret key and a corresponding public key.
  static Future<Map<String, Uint8List>> cryptoBoxKeypair() async {
    final Map result =
        await _channel.invokeMethod('crypto_box_keypair');
    return result.retype<String, Uint8List>();
  }

  /// Encrypts a message with a recipient's public key, a sender's secret key and a nonce.
  static Future<Uint8List> cryptoBoxEasy(
      Uint8List m, Uint8List n, Uint8List pk, Uint8List sk) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_box_easy', {'m': m, 'n': n, 'pk': pk, 'sk': sk});
    return result;
  }

  /// Verifies and decrypts a ciphertext produced by [cryptoBoxEasy].
  static Future<Uint8List> cryptoBoxOpenEasy(
      Uint8List c, Uint8List n, Uint8List pk, Uint8List sk) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_box_open_easy', {'c': c, 'n': n, 'pk': pk, 'sk': sk});
    return result;
  }

  /// Encrypts a message with a recipient's public key, a sender's secret key and a nonce. Returns the encrypted message and mac.
  static Future<Map<String, Uint8List>> cryptoBoxDetached(
      Uint8List m, Uint8List n, Uint8List pk, Uint8List sk) async {
    final Map result = await _channel.invokeMethod(
        'crypto_box_detached', {'m': m, 'n': n, 'pk': pk, 'sk': sk});
    return result.retype<String, Uint8List>();
  }

  /// Verifies and decrypts a ciphertext produced by [cryptoBoxDetached].
  static Future<Uint8List> cryptoBoxOpenDetached(Uint8List c, Uint8List mac,
      Uint8List n, Uint8List pk, Uint8List sk) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_box_open_detached',
        {'c': c, 'mac': mac, 'n': n, 'pk': pk, 'sk': sk});
    return result;
  }

  /// Computes a shared secret key given a public key and a secret key.
  static Future<Uint8List> cryptoBoxBeforenm(Uint8List pk, Uint8List sk) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_box_beforenm', {'pk': pk, 'sk': sk});
    return result;
  }

  /// Encrypts a message with a shared secret key and a nonce.
  static Future<Uint8List> cryptoBoxEasyAfternm(
      Uint8List m, Uint8List n, Uint8List k) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_box_easy_afternm', {'m': m, 'n': n, 'k': k});
    return result;
  }

  /// Verifies and decrypts a ciphertext with a shared secret key and a nonce.
  static Future<Uint8List> cryptoBoxOpenEasyAfternm(
      Uint8List c, Uint8List n, Uint8List k) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_box_open_easy_afternm', {'c': c, 'n': n, 'k': k});
    return result;
  }

  /// Encrypts a message with a shared secret key and a nonce. Returns the encrypted message and mac.
  static Future<Map<String, Uint8List>> cryptoBoxDetachedAfternm(
      Uint8List m, Uint8List n, Uint8List k) async {
    final Map result = await _channel
        .invokeMethod('crypto_box_detached_afternm', {'m': m, 'n': n, 'k': k});
    return result.retype<String, Uint8List>();
  }

  /// Verifies and decrypts a ciphertext with a mac, a shared secret key and a nonce.
  static Future<Uint8List> cryptoBoxOpenDetachedAfternm(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List k) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_box_open_detached_afternm',
        {'c': c, 'mac': mac, 'n': n, 'k': k});
    return result;
  }

  //
  // crypto_box_seal
  //
  /// Encrypts a message for a recipient whose public key is pk
  static Future<Uint8List> cryptoBoxSeal(Uint8List m, Uint8List pk) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_box_seal', {'m': m, 'pk': pk});
    return result;
  }

  /// Decrypts the ciphertext using specified key pair.
  static Future<Uint8List> cryptoBoxSealOpen(
      Uint8List c, Uint8List pk, Uint8List sk) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_box_seal_open', {'c': c, 'pk': pk, 'sk': sk});
    return result;
  }

  //
  // crypto_generichash
  //
  /// Computes a fingerprint of specified length for given input and key.
  static Future<Uint8List> cryptoGenerichash(
      int outlen, Uint8List i, Uint8List key) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_generichash', {'outlen': outlen, 'in': i, 'key': key});
    return result;
  }

  /// Initializes the hash state for the streaming API.
  static Future<Uint8List> cryptoGenerichashInit(
      Uint8List key, int outlen) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_generichash_init', {'key': key, 'outlen': outlen});
    return result;
  }

  /// Computes the hash for a part of a message.
  static Future<Uint8List> cryptoGenerichashUpdate(
      Uint8List state, Uint8List i) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_generichash_update', {'state': state, 'in': i});
    return result;
  }

  /// Completes the hash computation and returns the hash.
  static Future<Uint8List> cryptoGenerichashFinal(
      Uint8List state, int outlen) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_generichash_final', {'state': state, 'outlen': outlen});
    return result;
  }

  /// Generates a random key for generic hashing.
  static Future<Uint8List> cryptoGenerichashKeygen() async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_generichash_keygen');
    return result;
  }

  //
  // crypto_kdf
  //
  /// Creates a master key.
  static Future<Uint8List> cryptoKdfKeygen() async {
    final Uint8List result = await _channel.invokeMethod('crypto_kdf_keygen');
    return result;
  }

  /// Derives a subkey using a master key and a context.
  static Future<Uint8List> cryptoKdfDeriveFromKey(
      int subkeyLen, int subkeyId, Uint8List ctx, Uint8List key) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_kdf_derive_from_key', {
      'subkey_len': subkeyLen,
      'subkey_id': subkeyId,
      'ctx': ctx,
      'key': key
    });
    return result;
  }

  //
  // crypto_kx
  //
  /// Creates a new key pair.
  static Future<Map<String, Uint8List>> cryptoKxKeypair() async {
    final Map result =
        await _channel.invokeMethod('crypto_kx_keypair');
    return result.retype<String, Uint8List>();
  }

  /// Computes a deterministic key pair from the seed.
  static Future<Map<String, Uint8List>> cryptoKxSeedKeypair(
      Uint8List seed) async {
    final Map result =
        await _channel.invokeMethod('crypto_kx_seed_keypair', {'seed': seed});
    return result.retype<String, Uint8List>();
  }

  /// Computes a pair of shared keys (rx and tx) using the client's public key, the client's secret key and the server's public key.
  static Future<Map<String, Uint8List>> cryptoKxClientSessionKeys(
      Uint8List clientPk, Uint8List clientSk, Uint8List serverPk) async {
    final Map result = await _channel.invokeMethod(
        'crypto_kx_client_session_keys',
        {'client_pk': clientPk, 'client_sk': clientSk, 'server_pk': serverPk});
    return result.retype<String, Uint8List>();
  }

  /// Computes a pair of shared keys (rx and tx) using the server's public key, the server's secret key and the client's public key.
  static Future<Map<String, Uint8List>> cryptoKxServerSessionKeys(
      Uint8List serverPk, Uint8List serverSk, Uint8List clientPk) async {
    final Map result = await _channel.invokeMethod(
        'crypto_kx_server_session_keys',
        {'server_pk': serverPk, 'server_sk': serverSk, 'client_pk': clientPk});
    return result.retype<String, Uint8List>();
  }

  //
  // crypto_onetimeauth
  //
  /// Authenticates a message using a secret key.
  static Future<Uint8List> cryptoOnetimeauth(Uint8List i, Uint8List k) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_onetimeauth', {'in': i, 'k': k});
    return result;
  }

  /// Verifies that h is a correct authenticator for the message using given secret key.
  static Future<bool> cryptoOnetimeauthVerify(
      Uint8List h, Uint8List i, Uint8List k) async {
    final bool result = await _channel
        .invokeMethod('crypto_onetimeauth_verify', {'h': h, 'in': i, 'k': k});
    return result;
  }

  /// Initializes the authentication state for the streaming API.
  static Future<Uint8List> cryptoOnetimeauthInit(Uint8List key) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_onetimeauth_init', {'key': key});
    return result;
  }

  /// Computes the authenticator from sequential chunks of the message.
  static Future<Uint8List> cryptoOnetimeauthUpdate(
      Uint8List state, Uint8List i) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_onetimeauth_update', {'state': state, 'in': i});
    return result;
  }

  /// Completes the computation and returns the authenticator.
  static Future<Uint8List> cryptoOnetimeauthFinal(Uint8List state) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_onetimeauth_final', {'state': state});
    return result;
  }

  /// Generates a random key for use in onetime authentication.
  static Future<Uint8List> cryptoOnetimeauthKeygen() async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_onetimeauth_keygen');
    return result;
  }

  //
  // crypto_pwhash
  //
  /// Derives a key from a password and a salt.
  static Future<Uint8List> cryptoPwhash(int outlen, Uint8List passwd,
      Uint8List salt, int opslimit, int memlimit, int alg) async {
    final Uint8List result = await _channel.invokeMethod('crypto_pwhash', {
      'outlen': outlen,
      'passwd': passwd,
      'salt': salt,
      'opslimit': opslimit,
      'memlimit': memlimit,
      'alg': alg
    });
    return result;
  }

  /// Derives an ASCII encoded string containing a hash, automatically generated salt, and other parameters required to verify the password.
  static Future<Uint8List> cryptoPwhashStr(
      Uint8List passwd, int opslimit, int memlimit) async {
    final Uint8List result = await _channel.invokeMethod('crypto_pwhash_str', {
      'passwd': passwd,
      'opslimit': opslimit,
      'memlimit': memlimit,
    });
    return result;
  }

  /// Verifies that str is a valid password verification string.
  static Future<bool> cryptoPwhashStrVerify(
      Uint8List str, Uint8List passwd) async {
    final bool result = await _channel.invokeMethod(
        'crypto_pwhash_str_verify', {'str': str, 'passwd': passwd});
    return result;
  }

  /// Check if a password verification string matches the parameters opslimit and memlimit, and the current default algorithm.
  static Future<bool> cryptoPwhashStrNeedsRehash(
      Uint8List str, int opslimit, int memlimit) async {
    final bool result = await _channel.invokeMethod(
        'crypto_pwhash_str_needs_rehash',
        {'str': str, 'opslimit': opslimit, 'memlimit': memlimit});
    return result;
  }

  //
  // crypto_secretbox
  //
  /// Encrypts a message with a key and a nonce.
  static Future<Uint8List> cryptoSecretboxEasy(
      Uint8List m, Uint8List n, Uint8List k) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_secretbox_easy', {'m': m, 'n': n, 'k': k});
    return result;
  }

  /// Verifies and decrypts a ciphertext produced by [cryptoSecretboxEasy].
  static Future<Uint8List> cryptoSecretboxOpenEasy(
      Uint8List c, Uint8List n, Uint8List k) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_secretbox_open_easy', {'c': c, 'n': n, 'k': k});
    return result;
  }

  /// Encrypts a message with a key and a nonce, and returns the encrypted message and mac.
  static Future<Map<String, Uint8List>> cryptoSecretboxDetached(
      Uint8List m, Uint8List n, Uint8List k) async {
    final Map result = await _channel
        .invokeMethod('crypto_secretbox_detached', {'m': m, 'n': n, 'k': k});
    return result.retype<String, Uint8List>();
  }

  /// Verifies and decrypts an encrypted message.
  static Future<Uint8List> cryptoSecretboxOpenDetached(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List k) async {
    final Uint8List result = await _channel.invokeMethod(
        'crypto_secretbox_open_detached', {'c': c, 'mac': mac, 'n': n, 'k': k});
    return result;
  }

  /// Creates a random key
  static Future<Uint8List> cryptoSecretboxKeygen() async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_secretbox_keygen');
    return result;
  }

  //
  // crypto_scalarmult
  //
  /// Computes a public key given specified secret key.
  static Future<Uint8List> cryptoScalarmultBase(Uint8List n) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_scalarmult_base', {'n': n});
    return result;
  }

  /// Computes a shared secret given a user's secret key and another user's public key.
  static Future<Uint8List> cryptoScalarmult(Uint8List n, Uint8List p) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_scalarmult', {'n': n, 'p': p});
    return result;
  }

  //
  // crypto_shorthash
  //
  /// Computes a fixed-size fingerprint for specified input and key.
  static Future<Uint8List> cryptoShorthash(Uint8List i, Uint8List k) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_shorthash', {'in': i, 'k': k});
    return result;
  }

  /// Generates a random key.
  static Future<Uint8List> cryptoShorthashKeygen() async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_shorthash_keygen');
    return result;
  }

  //
  // crypto_sign
  //
  /// Deterministically derives a key pair from a single seed.
  static Future<Map<String, Uint8List>> cryptoSignSeedKeypair(
      Uint8List seed) async {
    final Map result =
        await _channel.invokeMethod('crypto_sign_seed_keypair', {'seed': seed});
    return result.retype<String, Uint8List>();
  }

  /// Randomly generates a secret key and a corresponding public key.
  static Future<Map<String, Uint8List>> cryptoSignKeypair() async {
    final Map result =
        await _channel.invokeMethod('crypto_sign_keypair');
    return result.retype<String, Uint8List>();
  }

  /// Prepends a signature to a message using specified secret key.
  static Future<Uint8List> cryptoSign(Uint8List m, Uint8List sk) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_sign', {'m': m, 'sk': sk});
    return result;
  }

  /// Checks that the signed message has a valid signature for specified public key.
  static Future<Uint8List> cryptoSignOpen(Uint8List sm, Uint8List pk) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_sign_open', {'sm': sm, 'pk': pk});
    return result;
  }

  /// Computes a signature for given message.
  static Future<Uint8List> cryptoSignDetached(Uint8List m, Uint8List sk) async {
    final Uint8List result =
        await _channel.invokeMethod('crypto_sign_detached', {'m': m, 'sk': sk});
    return result;
  }

  /// Verifies that the signature is valid for given message and signer's public key.
  static Future<bool> cryptoSignVerifyDetached(
      Uint8List sig, Uint8List m, Uint8List pk) async {
    final bool result = await _channel.invokeMethod(
        'crypto_sign_verify_detached', {'sig': sig, 'm': m, 'pk': pk});
    return result;
  }

  /// Initializes the sign state for the streaming API.
  static Future<Uint8List> cryptoSignInit() async {
    final Uint8List result = await _channel.invokeMethod('crypto_sign_init');
    return result;
  }

  /// Adds a new chunk to the message that will eventually be signed.
  static Future<Uint8List> cryptoSignUpdate(
      Uint8List state, Uint8List m) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_sign_update', {'state': state, 'm': m});
    return result;
  }

  /// Computes a signature for the previously supplied message, using the secret key.
  static Future<Uint8List> cryptoSignFinalCreate(
      Uint8List state, Uint8List sk) async {
    final Uint8List result = await _channel
        .invokeMethod('crypto_sign_final_create', {'state': state, 'sk': sk});
    return result;
  }

  /// Verifies whether the signature is valid for the message whose content has been previously supplied, using specified public key.
  static Future<bool> cryptoSignFinalVerify(
      Uint8List state, Uint8List sig, Uint8List pk) async {
    final bool result = await _channel.invokeMethod(
        'crypto_sign_final_verify', {'state': state, 'sig': sig, 'pk': pk});
    return result;
  }

  //
  // randombytes
  //
  /// Returns an unpredictable sequence of bytes of size [size].
  static Future<Uint8List> randombytesBuf(int size) async {
    final Uint8List result =
        await _channel.invokeMethod('randombytes_buf', {'size': size});
    return result;
  }

  /// Returns an unpredictable sequence of bytes of size [size] using given [seed].
  ///
  /// For a given seed, this function will always output the same sequence
  static Future<Uint8List> randombytesBufDeterministic(
      int size, Uint8List seed) async {
    final Uint8List result = await _channel.invokeMethod(
        'randombytes_buf_deterministic', {'size': size, 'seed': seed});
    return result;
  }

  /// Returns an unpredictable value between 0 and 0xffffffff (included).
  static Future<int> randombytesRandom() async {
    final int result = await _channel.invokeMethod('randombytes_random');
    return result;
  }

  /// Returns an unpredictable value between 0 and upper_bound (excluded).
  ///
  /// It guarantees a uniform distribution of the possible output values even when [upperBound] is not a power of 2.
  static Future<int> randombytesUniform(int upperBound) async {
    final int result = await _channel
        .invokeMethod('randombytes_uniform', {'upper_bound': upperBound});
    return result;
  }

  /// Reseeds the pseudo-random number generator.
  static Future<int> randombytesStir() async {
    final int result = await _channel.invokeMethod('randombytes_stir');
    return result;
  }

  /// Deallocates the global resources used by the pseudo-random number generator.
  ///
  /// Explicitly calling this function is almost never required.
  static Future<int> randombytesClose() async {
    final int result = await _channel.invokeMethod('randombytes_close');
    return result;
  }

  //
  // sodium_version
  //
  /// Retrieves the version of the loaded libsodium library (currently 1.0.16).
  static Future<String> sodiumVersionString() async {
    final String result = await _channel.invokeMethod('sodium_version_string');
    return result;
  }
}
