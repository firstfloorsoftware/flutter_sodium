import 'package:flutter/material.dart';
import 'samples.dart';
import 'package:flutter_sodium/flutter_sodium.dart';

void main() => runApp(new MyApp());

class MyApp extends StatelessWidget {
  runSamples() async {
    final version = await Sodium.sodiumVersionString();

    print('Sodium $version');

    await passwordHashingKeyDerivation();
    await passwordHashingStorage();
    await secretKeyAuthentication();
    await shortInputHashing();
    await generatingRandomData();

    print('Samples completed');
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
                  child: new Text('Run samples'), onPressed: runSamples))),
    );
  }
}
