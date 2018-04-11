import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'package:collection/collection.dart';

exampleCryptoAuth() async {
  // https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html
  printHeader('Secret key authentication');

  try {
    final message = utf8.encode('test');
    final key = await Sodium.cryptoAuthKeygen();
    final mac = await Sodium.cryptoAuth(message, key);

    print('mac: ${hex.encode(mac)}');

    final isValid = await Sodium.cryptoAuthVerify(mac, message, key);

    assert(isValid);
  } catch (e) {
    print(e);
  }
}

exampleCryptoBox() async {
  // https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
  printHeader('Public key authenticated encryption');

  try {
    final message = utf8.encode('test');
    final aliceKeypair = await Sodium.cryptoBoxKeypair();
    final bobKeypair = await Sodium.cryptoBoxKeypair();
    final nonce = await Sodium.randombytesBuf(crypto_box_NONCEBYTES);
    final cipherText = await Sodium.cryptoBoxEasy(
        message, nonce, bobKeypair['pk'], aliceKeypair['sk']);
    final decrypted = await Sodium.cryptoBoxOpenEasy(
        cipherText, nonce, aliceKeypair['pk'], bobKeypair['sk']);

    assert(const ListEquality().equals(message, decrypted));
  } catch (e) {
    print(e);
  }
}

exampleCryptoBoxDetached() async {
  // https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
  printHeader('Public key authenticated encryption (detached)');

  try {
    final message = utf8.encode('test');
    final aliceKeypair = await Sodium.cryptoBoxKeypair();
    final bobKeypair = await Sodium.cryptoBoxKeypair();
    final nonce = await Sodium.randombytesBuf(crypto_box_NONCEBYTES);
    final result = await Sodium.cryptoBoxDetached(
        message, nonce, bobKeypair['pk'], aliceKeypair['sk']);
    final decrypted = await Sodium.cryptoBoxOpenDetached(result['c'],
        result['mac'], nonce, aliceKeypair['pk'], bobKeypair['sk']);

    assert(const ListEquality().equals(message, decrypted));
  } catch (e) {
    print(e);
  }
}

exampleCryptoBoxPrecalculated() async {
  // https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
  printHeader('Public key authenticated encryption (precalculated)');

  try {
    final message = utf8.encode('test');
    final aliceKeypair = await Sodium.cryptoBoxKeypair();
    final bobKeypair = await Sodium.cryptoBoxKeypair();
    final nonce = await Sodium.randombytesBuf(crypto_box_NONCEBYTES);
    final aliceShared =
        await Sodium.cryptoBoxBeforenm(bobKeypair['pk'], aliceKeypair['sk']);
    final bobShared =
        await Sodium.cryptoBoxBeforenm(aliceKeypair['pk'], bobKeypair['sk']);

    final cipherText =
        await Sodium.cryptoBoxEasyAfternm(message, nonce, aliceShared);
    final decrypted =
        await Sodium.cryptoBoxOpenEasyAfternm(cipherText, nonce, bobShared);

    assert(const ListEquality().equals(message, decrypted));
  } catch (e) {
    print(e);
  }
}

exampleCryptoBoxPrecalculatedDetached() async {
  // https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
  printHeader('Public key authenticated encryption (precalculated detached)');

  try {
    final message = utf8.encode('test');
    final aliceKeypair = await Sodium.cryptoBoxKeypair();
    final bobKeypair = await Sodium.cryptoBoxKeypair();
    final nonce = await Sodium.randombytesBuf(crypto_box_NONCEBYTES);
    final aliceShared =
        await Sodium.cryptoBoxBeforenm(bobKeypair['pk'], aliceKeypair['sk']);
    final bobShared =
        await Sodium.cryptoBoxBeforenm(aliceKeypair['pk'], bobKeypair['sk']);

    final result =
        await Sodium.cryptoBoxDetachedAfternm(message, nonce, aliceShared);
    final decrypted = await Sodium.cryptoBoxOpenDetachedAfternm(
        result['c'], result['mac'], nonce, bobShared);

    assert(const ListEquality().equals(message, decrypted));
  } catch (e) {
    print(e);
  }
}

exampleCryptoBoxSeal() async {
  // https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html
  printHeader('Sealed boxes');

  try {
    final message = utf8.encode('Message');
    final recipientKeypair = await Sodium.cryptoBoxKeypair();
    final cipherText =
        await Sodium.cryptoBoxSeal(message, recipientKeypair['pk']);
    final decrypted = await Sodium.cryptoBoxSealOpen(
        cipherText, recipientKeypair['pk'], recipientKeypair['sk']);

    assert(const ListEquality().equals(message, decrypted));
  } catch (e) {
    print(e);
  }
}

exampleCryptoGenerichash() async {
  // https://download.libsodium.org/doc/hashing/generic_hashing.html
  printHeader('Generic hashing single part with key');
  try {
    final message = utf8.encode('Arbitrary data to hash');
    final key = await Sodium.cryptoGenerichashKeygen();
    final hash =
        await Sodium.cryptoGenerichash(crypto_generichash_BYTES, message, key);

    print('generichash: ${hex.encode(hash)}');
  } catch (e) {
    print(e);
  }
}

exampleCryptoGenericHashNoKey() async {
  // https://download.libsodium.org/doc/hashing/generic_hashing.html
  printHeader('Generic hashing single part without key');
  try {
    final message = utf8.encode('Arbitrary data to hash');
    final hash =
        await Sodium.cryptoGenerichash(crypto_generichash_BYTES, message, null);

    print('generichash: ${hex.encode(hash)}');
  } catch (e) {
    print(e);
  }
}

exampleCryptoGenerichashMultiPart() async {
  // https://download.libsodium.org/doc/hashing/generic_hashing.html
  printHeader('Generic hashing multi part with key');

  try {
    final messagePart1 = utf8.encode('Arbitrary data to hash');
    final messagePart2 = utf8.encode('is longer than expected');
    final key = await Sodium.cryptoGenerichashKeygen();
    var state =
        await Sodium.cryptoGenerichashInit(key, crypto_generichash_BYTES);

    state = await Sodium.cryptoGenerichashUpdate(state, messagePart1);
    state = await Sodium.cryptoGenerichashUpdate(state, messagePart2);
    final hash =
        await Sodium.cryptoGenerichashFinal(state, crypto_generichash_BYTES);

    print('generichash: ${hex.encode(hash)}');
  } catch (e) {
    print(e);
  }
}

exampleCryptoKdf() async {
  // https://download.libsodium.org/doc/key_derivation/
  printHeader('Key derivation');

  try {
    final ctx = utf8.encode('Examples');
    final masterKey = await Sodium.cryptoKdfKeygen();
    final subkey1 = await Sodium.cryptoKdfDeriveFromKey(32, 1, ctx, masterKey);
    final subkey2 = await Sodium.cryptoKdfDeriveFromKey(32, 2, ctx, masterKey);
    final subkey3 = await Sodium.cryptoKdfDeriveFromKey(64, 3, ctx, masterKey);

    print('subkey1: ${hex.encode(subkey1)}');
    print('subkey2: ${hex.encode(subkey2)}');
    print('subkey3: ${hex.encode(subkey3)}');
  } catch (e) {
    print(e);
  }
}

exampleCryptoKx() async {
  // https://download.libsodium.org/doc/key_exchange/
  printHeader('Key exchange');

  try {
    final clientKeypair = await Sodium.cryptoKxKeypair();
    final serverKeypair = await Sodium.cryptoKxKeypair();

    final clientKeys = await Sodium.cryptoKxClientSessionKeys(
        clientKeypair['pk'], clientKeypair['sk'], serverKeypair['pk']);
    final serverKeys = await Sodium.cryptoKxServerSessionKeys(
        serverKeypair['pk'], serverKeypair['sk'], clientKeypair['pk']);

    assert(const ListEquality().equals(clientKeys['rx'], serverKeys['tx']));
    assert(const ListEquality().equals(clientKeys['tx'], serverKeys['rx']));
  } catch (e) {
    print(e);
  }
}

exampleCryptoOnetimeauth() async {
  // https://download.libsodium.org/doc/advanced/poly1305.html
  printHeader('Secret-key single-message authentication');

  try {
    final message = utf8.encode('Data to authenticate');
    final key = await Sodium.cryptoOnetimeauthKeygen();
    final out = await Sodium.cryptoOnetimeauth(message, key);
    final valid = await Sodium.cryptoOnetimeauthVerify(out, message, key);

    assert(valid);
  } catch (e) {
    print(e);
  }
}

exampleCryptoOnetimeauthMultiPart() async {
  // https://download.libsodium.org/doc/advanced/poly1305.html
  printHeader('Secret-key single-message authentication (multi-part)');

  try {
    final message1 = utf8.encode('Multi-part');
    final message2 = utf8.encode('data');
    final key = await Sodium.cryptoOnetimeauthKeygen();

    var state = await Sodium.cryptoOnetimeauthInit(key);
    state = await Sodium.cryptoOnetimeauthUpdate(state, message1);
    state = await Sodium.cryptoOnetimeauthUpdate(state, message2);
    final out = await Sodium.cryptoOnetimeauthFinal(state);

    print('out: ${hex.encode(out)}');
  } catch (e) {
    print(e);
  }
}

exampleCryptoPwhash() async {
  // https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html
  printHeader('Password hashing key derivation');

  try {
    final password = utf8.encode('Correct Horse Battery Staple');
    final salt = await Sodium.randombytesBuf(crypto_pwhash_SALTBYTES);
    final hash = await Sodium.cryptoPwhash(
        crypto_box_SEEDBYTES,
        password,
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT);

    print('pwhash: ${hex.encode(hash)}');
  } catch (e) {
    print(e);
  }
}

exampleCryptoPwhashStr() async {
  // https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html
  printHeader('Password hashing storage');

  try {
    const opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    const memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    final password = utf8.encode('Correct Horse Battery Staple');
    final str = await Sodium.cryptoPwhashStr(password, opslimit, memlimit);
    final valid = await Sodium.cryptoPwhashStrVerify(str, password);

    // needsRehash not implemented for Android
    // final needsRehash =
    //     await Sodium.cryptoPwhashStrNeedsRehash(str, opslimit, memlimit);
    print(ascii.decode(str));

    assert(valid);
    //assert(!needsRehash);
  } catch (e) {
    print(e);
  }
}

exampleCryptoScalarmult() async {
  // https://download.libsodium.org/doc/advanced/scalar_multiplication.html
  printHeader('Diffie-Hellman function');

  try {
    /* Create client's secret and public keys */
    final clientSecretkey =
        await Sodium.randombytesBuf(crypto_box_SECRETKEYBYTES);
    final clientPublickey = await Sodium.cryptoScalarmultBase(clientSecretkey);

    /* Create server's secret and public keys */
    final serverSecretkey =
        await Sodium.randombytesBuf(crypto_box_SECRETKEYBYTES);
    final serverPublickey = await Sodium.cryptoScalarmultBase(serverSecretkey);

    /* The client derives a shared key from its secret key and the server's public key */
    /* shared key = h(q ‖ client_publickey ‖ server_publickey) */
    final scalarmultQByClient =
        await Sodium.cryptoScalarmult(clientSecretkey, serverPublickey);
    var h = await Sodium.cryptoGenerichashInit(null, crypto_generichash_BYTES);
    h = await Sodium.cryptoGenerichashUpdate(h, scalarmultQByClient);
    h = await Sodium.cryptoGenerichashUpdate(h, clientPublickey);
    h = await Sodium.cryptoGenerichashUpdate(h, serverPublickey);
    final sharedkeyByClient =
        await Sodium.cryptoGenerichashFinal(h, crypto_generichash_BYTES);

    /* The server derives a shared key from its secret key and the client's public key */
    /* shared key = h(q ‖ client_publickey ‖ server_publickey) */
    final scalarMultQByServer =
        await Sodium.cryptoScalarmult(serverSecretkey, clientPublickey);
    h = await Sodium.cryptoGenerichashInit(null, crypto_generichash_BYTES);
    h = await Sodium.cryptoGenerichashUpdate(h, scalarMultQByServer);
    h = await Sodium.cryptoGenerichashUpdate(h, clientPublickey);
    h = await Sodium.cryptoGenerichashUpdate(h, serverPublickey);
    final sharedkeyByServer =
        await Sodium.cryptoGenerichashFinal(h, crypto_generichash_BYTES);

    /* sharedkey_by_client and sharedkey_by_server are identical */
    assert(const ListEquality().equals(sharedkeyByClient, sharedkeyByServer));
  } catch (e) {
    print(e);
  }
}

exampleCryptoSecretbox() async {
  // https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html
  printHeader('Secret key authenticated encryption (combined mode)');

  try {
    final message = utf8.encode('test');
    final key = await Sodium.cryptoSecretboxKeygen();
    final nonce = await Sodium.randombytesBuf(crypto_secretbox_NONCEBYTES);
    final cipherText = await Sodium.cryptoSecretboxEasy(message, nonce, key);
    final decrypted =
        await Sodium.cryptoSecretboxOpenEasy(cipherText, nonce, key);

    assert(const ListEquality().equals(message, decrypted));
  } catch (e) {
    print(e);
  }
}

exampleCryptoSecretboxDetached() async {
  // https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html
  printHeader('Secret key authenticated encryption (detached mode)');

  try {
    final message = utf8.encode('test');
    final key = await Sodium.cryptoSecretboxKeygen();
    final nonce = await Sodium.randombytesBuf(crypto_secretbox_NONCEBYTES);
    final result = await Sodium.cryptoSecretboxDetached(message, nonce, key);
    final decrypted = await Sodium.cryptoSecretboxOpenDetached(
        result['c'], result['mac'], nonce, key);

    assert(const ListEquality().equals(message, decrypted));
  } catch (e) {
    print(e);
  }
}

exampleCryptoShorthash() async {
  // https://download.libsodium.org/doc/hashing/short-input_hashing.html
  printHeader('Short input hashing');

  try {
    final data = utf8.encode('Sparkling water');
    final key = await Sodium.cryptoShorthashKeygen();
    final hash = await Sodium.cryptoShorthash(data, key);

    print('shorthash: ${hex.encode(hash)}');
  } catch (e) {
    print(e);
  }
}

exampleCryptoSign() async {
  // https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
  printHeader('Public key signature combined');

  try {
    final message = utf8.encode('test');
    final keypair = await Sodium.cryptoSignKeypair();
    final signedMessage = await Sodium.cryptoSign(message, keypair['sk']);
    final unsignedMessage =
        await Sodium.cryptoSignOpen(signedMessage, keypair['pk']);

    assert(const ListEquality().equals(message, unsignedMessage));
  } catch (e) {
    print(e);
  }
}

exampleCryptoSignDetached() async {
  // https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
  printHeader('Public key signature detached');
  try {
    final message = utf8.encode('test');
    final keypair = await Sodium.cryptoSignKeypair();
    final sig = await Sodium.cryptoSignDetached(message, keypair['sk']);

    final valid =
        await Sodium.cryptoSignVerifyDetached(sig, message, keypair['pk']);

    assert(valid);
  } catch (e) {
    print(e);
  }
}

exampleCryptoSignMultiPart() async {
  // https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
  printHeader('Public key signature multi-part');
  try {
    final messagePart1 = utf8.encode('Arbitrary data to hash');
    final messagePart2 = utf8.encode('is longer than expected');

    final keypair = await Sodium.cryptoSignKeypair();

    /* signature creation */
    var state = await Sodium.cryptoSignInit();
    state = await Sodium.cryptoSignUpdate(state, messagePart1);
    state = await Sodium.cryptoSignUpdate(state, messagePart2);
    final sig = await Sodium.cryptoSignFinalCreate(state, keypair['sk']);

    /* signature verification */
    final valid = await Sodium.cryptoSignFinalVerify(state, sig, keypair['pk']);

    assert(valid);
  } catch (e) {
    print(e);
  }
}

exampleRandombytes() async {
  // https://download.libsodium.org/doc/generating_random_data/
  printHeader('Generating random data');

  try {
    final rnd = await Sodium.randombytesRandom();
    final rndUniform = await Sodium.randombytesUniform(100);
    final rndBuf = await Sodium.randombytesBuf(16);

    print('random: $rnd');
    print('random uniform: $rndUniform');
    print('random buffer: ${hex.encode(rndBuf)}');
  } catch (e) {
    print(e);
  }
}

printHeader(String value) {
  print('--\n$value');
}
