import 'dart:typed_data';
import 'names.dart';

/// Detached cipher and associated authentication tag.
class DetachedCipher {
  final Uint8List cipher, mac;

  const DetachedCipher(this.cipher, this.mac);
  DetachedCipher.fromMap(Map<String, Uint8List> map)
      : this(map[Names.c], map[Names.mac]);
}
