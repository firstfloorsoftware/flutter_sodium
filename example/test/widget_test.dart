import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'dart:typed_data';

void main() {
  final List<MethodCall> log = <MethodCall>[];
  const MethodChannel channel = MethodChannel('flutter_sodium');
  channel.setMockMethodCallHandler((MethodCall methodCall) async {
    log.add(methodCall);
  });

  tearDown(() {
    log.clear();
  });

  group('CryptoAuth', () {
    test('CryptoAuth.generateKey', () async {
      await CryptoAuth.generateKey();
      expect(
          log, <Matcher>[isMethodCall('crypto_auth_keygen', arguments: null)]);
    });

    test('CryptoAuth.compute does not accept null value', () async {
      expect(() async => await CryptoAuth.compute(null, null),
          throwsAssertionError);
    });
    test('CryptoAuth.compute does not accept null key', () async {
      expect(() async => await CryptoAuth.compute('hello world', null),
          throwsAssertionError);
    });

    test('CryptoAuth.compute does not accept key of invalid length', () async {
      expect(
          () async => await CryptoAuth.compute('hello world', new Uint8List(1)),
          throwsRangeError);
    });
  });

  group('RandomBytes', () {
    test('RandomBytes.buffer', () async {
      await RandomBytes.buffer(16);
      expect(log, <Matcher>[
        isMethodCall('randombytes_buf',
            arguments: <String, dynamic>{'size': 16})
      ]);
    });

    test('RandomBytes.random', () async {
      await RandomBytes.random();
      expect(
          log, <Matcher>[isMethodCall('randombytes_random', arguments: null)]);
    });

    test('RandomBytes.uniform', () async {
      await RandomBytes.uniform(16);
      expect(log, <Matcher>[
        isMethodCall('randombytes_uniform',
            arguments: <String, dynamic>{'upper_bound': 16})
      ]);
    });
  });
}
