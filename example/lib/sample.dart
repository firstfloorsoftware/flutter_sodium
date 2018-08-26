import 'package:flutter/material.dart';
import 'dart:async';

typedef Future<String> SampleFunction();

class Sample extends StatelessWidget {
  final String _title;
  final String _code;
  final String _description;
  final SampleFunction _sample;
  Sample(this._title, this._description, this._code, this._sample);

  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Padding(
          padding: EdgeInsets.only(bottom: 16.0),
          child: Text(_title, style: Theme.of(context).textTheme.title)),
      Padding(
          padding: EdgeInsets.only(bottom: 16.0), child: Text(_description)),
      CodeBlock(_code),
      SampleRunner(_sample)
    ]);
  }
}

class SampleRunner extends StatefulWidget {
  final SampleFunction _sample;

  SampleRunner(this._sample);

  @override
  State<StatefulWidget> createState() => _SampleRunnerState();
}

class _SampleRunnerState extends State<SampleRunner> {
  Future<String> _sampleRun;

  runSample() {
    setState(() {
      _sampleRun = widget._sample();
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_sampleRun == null) {
      return Padding(
          padding: EdgeInsets.only(top: 16.0), child: RunButton(runSample));
    }

    return FutureBuilder<String>(
      future: _sampleRun,
      builder: (BuildContext context, AsyncSnapshot<String> snapshot) {
        final children = <Widget>[
          Padding(
              padding: EdgeInsets.symmetric(vertical: 16.0),
              child: RunButton(snapshot.connectionState == ConnectionState.done
                  ? runSample
                  : null)),
          Padding(
              padding: EdgeInsets.only(bottom: 16.0),
              child:
                  Text('Result', style: TextStyle(fontWeight: FontWeight.bold)))
        ];

        if (snapshot.connectionState == ConnectionState.done) {
          children.add(CodeBlock(
              snapshot.hasError ? snapshot.error.toString() : snapshot.data,
              color: snapshot.hasError
                  ? Colors.red.shade200
                  : Colors.green.shade200));
        } else {
          children.add(Center(child: CircularProgressIndicator()));
        }

        return Column(
            crossAxisAlignment: CrossAxisAlignment.start, children: children);
      },
    );
  }
}

class RunButton extends StatelessWidget {
  final VoidCallback onPressed;

  RunButton(this.onPressed);

  @override
  Widget build(BuildContext context) {
    return RaisedButton(
        child: Text('Run'),
        textColor: Colors.white,
        color: Theme.of(context).accentColor,
        onPressed: onPressed);
  }
}

class CodeBlock extends StatelessWidget {
  final String _code;
  final Color color;

  CodeBlock(this._code, {this.color = Colors.black12});

  @override
  Widget build(BuildContext context) {
    return Container(
        padding: EdgeInsets.all(10.0),
        color: color,
        child: Text(_code ?? "(null)",
            style: TextStyle(fontFamily: 'RobotoMono', fontSize: 12.0)));
  }
}
