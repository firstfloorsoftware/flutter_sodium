import 'package:flutter/material.dart';
import 'example_page.dart';
import 'sample.dart';

class Example {
  final String title;
  final bool isHeader;
  final String description;
  final String docUrl;
  final List<Sample> samples;

  const Example(this.title,
      {this.isHeader = false, this.description, this.docUrl, this.samples});

  void navigate(BuildContext context) {
    Navigator.push(context,
        new MaterialPageRoute(builder: (context) => ExamplePage(this)));
  }
}

