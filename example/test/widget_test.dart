import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'dart:typed_data';
import 'dart:convert';

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
    test('generateKey', () async {
      await CryptoAuth.generateKey();
      expect(
          log, <Matcher>[isMethodCall('crypto_auth_keygen', arguments: null)]);
    });

    test('compute', () async {
      await CryptoAuth.compute('hello world', new Uint8List(32));
      expect(log, <Matcher>[
        isMethodCall('crypto_auth', arguments: <String, dynamic>{
          'in': utf8.encode('hello world'),
          'k': new Uint8List(32)
        })
      ]);
    });

    test('verify', () async {
      await CryptoAuth.verify(new Uint8List(32), 'hello world', new Uint8List(32));
      expect(log, <Matcher>[
        isMethodCall('crypto_auth_verify', arguments: <String, dynamic>{
          'h': new Uint8List(32),
          'in': utf8.encode('hello world'),
          'k': new Uint8List(32)
        })
      ]);
    });

    test('compute does not accept null value', () async {
      expect(() async => await CryptoAuth.compute(null, new Uint8List(1)),
          throwsAssertionError);
    });
    test('compute does not accept null key', () async {
      expect(() async => await CryptoAuth.compute('hello world', null),
          throwsAssertionError);
    });

    test('compute does not accept key of invalid length', () async {
      expect(
          () async => await CryptoAuth.compute('hello world', new Uint8List(1)),
          throwsA(allOf(
              isRangeError,
              predicate((e) =>
                  e.toString() ==
                  'RangeError (k): Invalid length: Only valid value is 32: 1'))));
    });

    test('verify does not accept null tag', () async {
      expect(
          () async => await CryptoAuth.verify(null, 'hello world', new Uint8List(32)),
          throwsAssertionError);
    });

    test('verify does not accept null value', () async {
      expect(
          () async => await CryptoAuth.verify(new Uint8List(32), null, new Uint8List(32)),
          throwsAssertionError);
    });

    test('verify does not accept null key', () async {
      expect(
          () async => await CryptoAuth.verify(new Uint8List(32), 'hello world', null),
          throwsAssertionError);
    });

    test('verify does not accept tag of invalid length', () async {
      expect(
          () async => await CryptoAuth.verify(new Uint8List(1), 'hello world', new Uint8List(32)),
          throwsA(allOf(
              isRangeError,
              predicate((e) =>
                  e.toString() ==
                  'RangeError (h): Invalid length: Only valid value is 32: 1'))));
    });

    test('verify does not accept key of invalid length', () async {
      expect(
          () async => await CryptoAuth.verify(new Uint8List(32), 'hello world', new Uint8List(1)),
          throwsA(allOf(
              isRangeError,
              predicate((e) =>
                  e.toString() ==
                  'RangeError (k): Invalid length: Only valid value is 32: 1'))));
    });
  });

  group('RandomBytes', () {
    test('buffer', () async {
      await RandomBytes.buffer(16);
      expect(log, <Matcher>[
        isMethodCall('randombytes_buf',
            arguments: <String, dynamic>{'size': 16})
      ]);
    });

    test('random', () async {
      await RandomBytes.random();
      expect(
          log, <Matcher>[isMethodCall('randombytes_random', arguments: null)]);
    });

    test('uniform', () async {
      await RandomBytes.uniform(16);
      expect(log, <Matcher>[
        isMethodCall('randombytes_uniform',
            arguments: <String, dynamic>{'upper_bound': 16})
      ]);
    });
  });
}
