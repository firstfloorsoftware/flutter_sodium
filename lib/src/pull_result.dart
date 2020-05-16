import 'dart:typed_data';
import 'package:flutter/foundation.dart';

class PullResult {
  final Uint8List m;
  final int tag;

  const PullResult({@required this.m, @required this.tag});
}
