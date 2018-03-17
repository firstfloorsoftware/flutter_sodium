# flutter_sodium

A serious framework needs a serious cryptographic library. With flutter_sodium you get access to the modern, easy-to-use [libsodium](https://download.libsodium.org/doc/) crypto library in your [Flutter](https://flutter.io) apps. One set of crypto APIs supporting both Android and iOS.

## API coverage
At this point in time flutter_sodium implements the following libsodium APIs:
- crypto_auth
- crypto_box_seal
- crypto_generichash
- crypto_pwhash
- crypto_secretbox
- crypto_shorthash
- randombytes
- sodium_version

## Roadmap
1) A core API that maps 1:1 to libsodium functions. Initial version should include as many APIs to make it usable.
2) A Dart-friendly, opinionated API wrapping the core API. Should work with types other than Uint8List such as strings, streams, etc.

## How it works
The flutter_sodium plugin includes the native libsodium binaries compiled for Android and iOS. Since Flutter does not support native binaries (see also https://github.com/flutter/flutter/issues/7053), a [platform channel](https://flutter.io/platform-channels/) is established to enable native function invocation. One side effect of this approach is that the entire flutter_sodium API is asynchronous. This is great for potential long-running operations such as Argon password hashing, but does not make much sense for other short-running functions.

## Getting Started

This plugin is very much work in progress, and not available yet in [Dart Pub](https://pub.dartlang.org/).