import 'package:flutter/material.dart';
import 'examples.dart';
import 'package:flutter_sodium/flutter_sodium.dart';

void main() => runApp(new MyApp());

class MyApp extends StatelessWidget {
  runExamples() async {
    final version = await Sodium.sodiumVersionString();

    print('Sodium $version');

    await exampleCryptoAuth();
    await exampleCryptoBox();
    await exampleCryptoBoxDetached();
    await exampleCryptoBoxPrecalculated();
    await exampleCryptoBoxPrecalculatedDetached();
    await exampleCryptoBoxSeal();
    await exampleCryptoGenerichash();
    await exampleCryptoGenericHashNoKey();
    await exampleCryptoGenerichashMultiPart();
    await exampleCryptoKdf();
    await exampleCryptoKx();
    await exampleCryptoOnetimeauth();
    await exampleCryptoOnetimeauthMultiPart();
    await exampleCryptoPwhash();
    await exampleCryptoPwhashStr();
    await exampleCryptoScalarmult();
    await exampleCryptoSecretbox();
    await exampleCryptoSecretboxDetached();
    await exampleCryptoShorthash();
    await exampleCryptoSign();
    await exampleCryptoSignDetached();
    await exampleCryptoSignMultiPart();
    await exampleRandombytes();

    print('Examples completed');
  }

  @override
  Widget build(BuildContext context) {
    return new MaterialApp(
      home: new Scaffold(
          appBar: new AppBar(
            title: new Text('Flutter Sodium'),
          ),
          body: new Center(
              child: new RaisedButton(
                  child: new Text('Run samples'), onPressed: runExamples))),
    );
  }
}
