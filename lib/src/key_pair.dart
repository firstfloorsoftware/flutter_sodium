import 'dart:typed_data';
import 'names.dart';

/// Represents a secret key and a corresponding public key.
class KeyPair {
  final Uint8List publicKey, secretKey;

  const KeyPair(this.publicKey, this.secretKey);
  KeyPair.fromMap(Map<String, Uint8List> map)
      : this(map[Names.pk], map[Names.sk]);
}
