import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'package:convert/convert.dart';

void main() {
  setUp(() {});

  tearDown(() {});

  group('crypto_pwhash', () {
    test('consts', () {
      expect(Sodium.cryptoPwhashAlgArgon2i13, 1,
          reason: 'cryptoPwhashAlgArgon2i13');
      expect(Sodium.cryptoPwhashAlgArgon2id13, 2,
          reason: 'cryptoPwhashAlgArgon2id13');
      expect(Sodium.cryptoPwhashAlgDefault, 2,
          reason: 'cryptoPwhashAlgDefault');
    });
  });
}
