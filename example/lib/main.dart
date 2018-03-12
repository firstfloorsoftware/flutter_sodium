import 'package:flutter/material.dart';
import 'samples.dart';

void main() => runApp(new MyApp());

class MyApp extends StatelessWidget {
  runSamples() async {
    var stopwatch = new Stopwatch()..start();
    print('Running sodium samples');

    await secretKeyAuthentication();
    await shortInputHashing();
    await generatingRandomData();

    print('Samples took ${stopwatch.elapsedMilliseconds}ms');
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
