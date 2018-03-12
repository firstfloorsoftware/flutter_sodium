import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:flutter_sodium/flutter_sodium.dart';

shortInputHashing() async {
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

generatingRandomData() async{
  // https://download.libsodium.org/doc/generating_random_data/

  printHeader('Generating random data');
  try{
    final rnd = await Sodium.randombytesRandom();
    final rndUniform = await Sodium.randombytesUniform(100);
    final rndBuf = await Sodium.randombytesBuf(16);

    print('random: $rnd');
    print('random uniform: $rndUniform');
    print('random buffer: ${hex.encode(rndBuf)}');
  } catch(e) {
    print(e);
  }
}

printHeader(String value)
{
  print('--\n$value');
}