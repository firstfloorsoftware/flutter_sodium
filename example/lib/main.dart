import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'package:convert/convert.dart';

void main() {
  Sodium.sodiumInit();
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: MyHomePage(title: 'flutter_sodium demo'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  MyHomePage({Key key, this.title}) : super(key: key);

  final String title;

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  String _;

  void _runTests() {
    setState(() {
      final buf = Sodium.randombytesBuf(4);

      print(hex.encode(buf));
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
        appBar: AppBar(
          title: Text(widget.title),
        ),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              Text(
                'Hit refresh to re-run tests',
              ),
            ],
          ),
        ),
        floatingActionButton: FloatingActionButton(
          onPressed: _runTests,
          tooltip: 'Refresh',
          child: Icon(Icons.refresh),
        ));
  }
}
