import 'dart:async';
import 'package:flutter/services.dart';

/// Sodium is a modern, easy-to-use software library for encryption, decryption, signatures, password hashing and more.
class Sodium {
  static const MethodChannel _channel = const MethodChannel('flutter_sodium');

  //
  // sodium_version
  //
  static Future<String> sodiumVersionString() =>
      _channel.invokeMethod('sodium_version_string');
}
