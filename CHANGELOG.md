## 0.0.10 - June 27, 2019
* Adds support for kdf to Android (by rmtmckenzie)
* Update to Swift 5 & fix all warnings in iOS code (by rmtmckenzie)

## 0.0.9 - February 24, 2019
* Adds support for crypto_sign_ed25519_sk_to_curve25519 (by sporkins)
* Fixes sample app issues

## 0.0.8 - September 10, 2018
* Adds support for crypto_box_curve25519xchacha20poly1305_*
* Fixes iOS build warnings

## 0.0.7 - August 28, 2018
* Adds support for executing crypto tasks on a background thread
* Implements missing Android bindings for crypto_aead_*
* Completes argument assertions and range checks 

## 0.0.6 - August 21, 2018
* Adds ChaCha20Poly1305, ChaCha20Poly1305Ietf and XChaCha20Poly1305Ietf APIs
* Adds argument assertions and range checks 
* Upgrades libsodiumjni dependency to v2.0.1

## 0.0.5 - August 5, 2018
* Breaking high-level API changes
  * String operations now default
  * Randombytes renamed to RandomBytes
* Adds CryptoBox, KeyDerivation, KeyExchange and ScalarMult highlevel APIs 

## 0.0.4 - July 31, 2018
* No functional changes
* Fixes SDK constraint and source file formatting

## 0.0.3 - July 30, 2018
* Adds Dart-friendly APIs
* Introduces example app with runnable code samples 
* Replaces deprecated code constructs

## 0.0.2 - April 12, 2018
* Adds support for Flutter Beta 2 and Dart 2

## 0.0.1 - March 20, 2018
* Initial release with core libsodium API support.
