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
    await exampleCryptoGenerichashStream();
    await exampleCryptoKx();
    await exampleCryptoPwhash();
    await exampleCryptoPwhashStr();
    await exampleCryptoSecretbox();
    await exampleCryptoSecretboxDetached();
    await exampleCryptoShorthash();
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
