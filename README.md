# flutter_sodium

With flutter_sodium you get access to the modern, easy-to-use [libsodium](https://download.libsodium.org/doc/) crypto library in your [Flutter](https://flutter.io) apps. One set of crypto APIs supporting both Android and iOS.

## API coverage
At this point in time flutter_sodium implements the following high-level libsodium APIs:
- crypto_auth
- crypto_box
- crypto_generichash
- crypto_kdf
- crypto_kx
- crypto_onetimeauth
- crypto_pwhash
- crypto_scalarmult
- crypto_secretbox
- crypto_shorthash
- crypto_sign
- randombytes
- sodium_version

## Roadmap
1) A core API that maps 1:1 to libsodium functions. Should cover the entire high-level API.
2) Proper argument checks
3) Fix missing API functions (such as crypto_pwhash_str_needs_rehash)
4) A Dart-friendly, opinionated API wrapping the core API. Should work with types other than Uint8List such as strings, streams, etc.

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
const opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
const memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
final password = utf8.encode('my password');
final str = await Sodium.cryptoPwhashStr(password, opslimit, memlimit);

print('Password hash str: ${ascii.decode(str)}');

// verify hash str
final valid = await Sodium.cryptoPwhashStrVerify(str, password);

assert(valid);
```

## Current issues
- Some APIs are not available yet in Android
- Getting a Swift plugin to work nicely with Flutter on iOS is a painful operation. See als https://github.com/flutter/flutter/issues/16049
- Since Flutter does not support native binaries (see also https://github.com/flutter/flutter/issues/7053), a [platform channel](https://flutter.io/platform-channels/) is established to enable native function invocation. One side effect of this approach is that the entire flutter_sodium API is asynchronous. This is great for potential long-running operations such as Argon password hashing, but does not make much sense for other short-running functions.