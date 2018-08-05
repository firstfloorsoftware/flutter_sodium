import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import 'example.dart';

class ExamplePage extends StatelessWidget {
  final Example _example;
  ExamplePage(this._example);

  @override
  Widget build(BuildContext context) {
    final children = <Widget>[];

    if (_example.description != null) {
      children.add(Padding(
          padding: EdgeInsets.only(bottom: 16.0),
          child: Text(_example.description)));
    }

    if (_example.docUrl != null) {
      children.add(Padding(
          padding: EdgeInsets.only(bottom: 16.0),
          child: InkWell(
              child: Text(
                'More information',
                style: TextStyle(color: Theme.of(context).accentColor),
              ),
              onTap: () => launch(_example.docUrl))));
    }

    if (_example.samples != null) {
      for (var sample in _example.samples) {
        children.add(
            Padding(padding: EdgeInsets.only(bottom: 16.0), child: sample));
      }
    }

    return Scaffold(
        appBar: AppBar(
          title: Text(_example.title),
        ),
        body: SingleChildScrollView(
            child: Container(
                padding: EdgeInsets.all(15.0),
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: children))));
  }
}
