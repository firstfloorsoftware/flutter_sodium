import 'dart:typed_data';

/// Represents a secret key and a corresponding public key.
class KeyPair {
  final Uint8List publicKey, secretKey;

  const KeyPair(this.publicKey, this.secretKey);
  KeyPair.fromMap(Map<String, Uint8List> map) : this(map['pk'], map['sk']);
}
