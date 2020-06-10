import 'dart:typed_data';
import 'package:flutter/foundation.dart';

/// Detached cipher and associated authentication tag.
class DetachedCipher {
  final Uint8List c, mac;

  const DetachedCipher({@required this.c, @required this.mac});
}
