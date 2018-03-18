import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'package:collection/collection.dart';

exampleCryptoAuth() async {
  // https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html
  printHeader('Secret key authentication');

  try {
    final message = UTF8.encode('test');
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
    final message = UTF8.encode('test');
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
    final message = UTF8.encode('test');
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
    final message = UTF8.encode('test');
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
    final message = UTF8.encode('test');
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
    final message = UTF8.encode('Message');
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
    final message = UTF8.encode('Arbitrary data to hash');
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
    final message = UTF8.encode('Arbitrary data to hash');
    final hash =
        await Sodium.cryptoGenerichash(crypto_generichash_BYTES, message, null);

    print('generichash: ${hex.encode(hash)}');
  } catch (e) {
    print(e);
  }
}

exampleCryptoGenerichashStream() async {
  // https://download.libsodium.org/doc/hashing/generic_hashing.html
  printHeader('Generic hashing multi part with key');

  try {
    final messagePart1 = UTF8.encode('Arbitrary data to hash');
    final messagePart2 = UTF8.encode('is longer than expected');
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
    final message = UTF8.encode('Data to authenticate');
    final key = await Sodium.cryptoOnetimeauthKeygen();
    final out = await Sodium.cryptoOnetimeauth(message, key);
    final valid = await Sodium.cryptoOnetimeauthVerify(out, message, key);

    assert(valid);
  } catch(e) {
    print(e);
  }
}

exampleCryptoOnetimeauthStream() async {
  // https://download.libsodium.org/doc/advanced/poly1305.html
  printHeader('Secret-key single-message authentication (streaming)');

  try {
    final message1 = UTF8.encode('Multi-part');
    final message2 = UTF8.encode('data');
    final key = await Sodium.cryptoOnetimeauthKeygen();

    var state = await Sodium.cryptoOnetimeauthInit(key);
    state = await Sodium.cryptoOnetimeauthUpdate(state, message1);
    state = await Sodium.cryptoOnetimeauthUpdate(state, message2);
    final out = await Sodium.cryptoOnetimeauthFinal(state);
    
    print('out: ${hex.encode(out)}');
  } catch(e) {
    print(e);
  }
}

exampleCryptoPwhash() async {
  // https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html
  printHeader('Password hashing key derivation');

  try {
    final password = UTF8.encode('Correct Horse Battery Staple');
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
    final password = UTF8.encode('Correct Horse Battery Staple');
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

exampleCryptoSecretbox() async {
  // https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html
  printHeader('Secret key authenticated encryption (combined mode)');

  try {
    final message = UTF8.encode('test');
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
    final message = UTF8.encode('test');
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
    final data = UTF8.encode('Sparkling water');
    final key = await Sodium.cryptoShorthashKeygen();
    final hash = await Sodium.cryptoShorthash(data, key);

    print('shorthash: ${hex.encode(hash)}');
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
