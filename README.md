# flutter_sodium

With flutter_sodium you get access to the modern, easy-to-use [libsodium](https://download.libsodium.org/doc/) crypto library in your [Flutter](https://flutter.io) apps. One set of crypto APIs supporting both Android and iOS.

[![Pub](https://img.shields.io/pub/v/flutter_sodium.svg)](https://pub.dartlang.org/packages/flutter_sodium)

## Getting Started

In your flutter project add the dependency:

```yml
dependencies:
  ...
  flutter_sodium: any
```
## Usage example

```dart
import 'package:flutter_sodium/flutter_sodium.dart';

// Password hashing (using Argon)
final password = 'my password';
final str = PasswordHash.hashStringStorage(password);

print(str);

// verify hash str
final valid = PasswordHash.verifyStorage(str, password);

assert(valid);
```

This project includes an extensive example app with runnable code samples. Be sure to check it out!

<img src="https://raw.githubusercontent.com/firstfloorsoftware/flutter_sodium/master/example/assets/screenshots/screenshot1.png" width="300">

## API coverage
The flutter_sodium plugin implements the following libsodium APIs:
- crypto_auth
- crypto_box
- crypto_generichash
- crypto_kdf
- crypto_pwhash
- crypto_secretbox
- crypto_shorthash
- crypto_sign
- randombytes
- sodium_version

API coverage is not 100% complete, track the progress in issue #35.

## Dart APIs
The plugin includes a core API that maps native libsodium functions 1:1 to Dart equivalents. The core API is available in the class [`Sodium`](https://github.com/firstfloorsoftware/flutter_sodium/blob/master/lib/flutter_sodium.dart). Dart naming conventions are used for core API function names. A native libsodium function such as `crypto_pwhash_str`, is available in flutter as `Sodium.cryptoPwhashStr`.

Also included in flutter_sodium is a high-level, opinionated API providing access to libsodium in a Dart friendly manner. The various functions are available in separate Dart classes. Password hashing for example is available in the `PasswordHash` class. The high-level API depends on the core API to get things done.

## Known issues
- Previous incarnations of flutter_sodium used platform channels for native interop. The latest version has been rewritten to take full advantage of Dart FFI. FFI offers fast native interop and is the obvious choice for flutter_sodium. One minor problem, FFI is still in beta and its API may change. This may affect flutter_sodium.