import 'dart:async';

import 'package:flutter/services.dart';

class FlutterSodium {
  static const MethodChannel _channel =
      const MethodChannel('flutter_sodium');

  static Future<String> get platformVersion =>
      _channel.invokeMethod('getPlatformVersion');
}
