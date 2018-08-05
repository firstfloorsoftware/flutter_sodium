import 'dart:typed_data';

/// Detached cipher and associated authentication tag.
class DetachedCipher {
  final Uint8List cipher;
  final Uint8List mac;

  const DetachedCipher(this.cipher, this.mac);
  DetachedCipher.fromMap(Map<String, Uint8List> map)
      : this(map['c'], map['mac']);
}
