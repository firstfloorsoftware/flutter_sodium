import 'dart:ffi';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';

class InitPushResult {
  final Pointer<Uint8> state;
  final Uint8List header;

  const InitPushResult({@required this.state, @required this.header});
}
