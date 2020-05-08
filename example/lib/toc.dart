import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'package:convert/convert.dart';

typedef void PrintFunc(Object o);
typedef void SampleFunc(PrintFunc print);
typedef Future SampleFuncAsync(PrintFunc print);

class Section extends Topic {
  Section(String title) : super(title);
}

class Topic {
  final String title;
  final String description;
  final String url;
  final List<Sample> samples;

  Topic(this.title, {this.description, this.url, this.samples});
}

class Sample {
  final String title;
  final String description;
  final String name;
  final SampleFunc func;
  final SampleFuncAsync funcAsync;
  String code;

  Sample(this.title, {this.description, this.name, this.func, this.funcAsync});
}

Future<List<Topic>> buildToc(BuildContext context) async {
  final toc = [
    Section('Common'),
    Topic('Random data',
        description:
            'Provides a set of functions to generate unpredictable data, suitable for creating secret keys.',
        url: 'https://libsodium.gitbook.io/doc/generating_random_data/',
        samples: <Sample>[
          Sample('Random',
              description:
                  'Returns an unpredictable value between 0 and 0xffffffff (included).',
              name: 'random1', func: (PrintFunc print) {
            // BEGIN random1
            final rnd = RandomBytes.random();
            print(rnd.toRadixString(16));
            // END random1
          }),
          Sample('Uniform',
              description:
                  'Generates an unpredictable value between 0 and upperBound (excluded).',
              name: 'random2', func: (PrintFunc print) {
            // BEGIN random2
            final rnd = RandomBytes.uniform(16);
            print(rnd);
            // END random2
          }),
          Sample('Buffer',
              description:
                  'Generates an unpredictable sequence of bytes of specified size.',
              name: 'random3', func: (PrintFunc print) {
            // BEGIN random3
            final buf = RandomBytes.buffer(16);
            print(hex.encode(buf));
            // END random3
          })
        ]),
    Topic('Version',
        description: 'Provides libsodium version info.',
        url: 'https://libsodium.gitbook.io/doc/',
        samples: <Sample>[
          Sample('Usage',
              description:
                  'Retrieves the version details of the loaded libsodium library.',
              name: 'version1', func: (PrintFunc print) {
            // BEGIN version1
            final version = Sodium.sodiumVersionString;
            final major = Sodium.sodiumLibraryVersionMajor;
            final minor = Sodium.sodiumLibraryVersionMinor;

            print('$version ($major.$minor)');
            // END version1
          })
        ]),
    Section('Secret-key cryptography'),
    Topic('Authenticated encryption',
        description: 'Secret-key encryption and verification',
        url:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox',
        samples: <Sample>[]),
    Topic('Authentication',
        description:
            'Computes an authentication tag for a message and a secret key, and provides a way to verify that a given tag is valid for a given message and a key.',
        url:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/secret-key_authentication',
        samples: <Sample>[]),
    Topic('Original ChaCha20-Poly1305',
        description: 'Authenticated Encryption with Additional Data.',
        url:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/original_chacha20-poly1305_construction',
        samples: <Sample>[]),
    Topic('IETF ChaCha20-Poly1305',
        description: 'Authenticated Encryption with Additional Data',
        url:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction',
        samples: <Sample>[]),
    Topic('XChaCha20-Poly1305',
        description: 'Authenticated Encryption with Additional Data.',
        url:
            'https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction',
        samples: <Sample>[]),
    Section('Public-key cryptography'),
    Topic('Authenticated encryption',
        description: 'Public-key authenticated encryption',
        url:
            'https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption',
        samples: <Sample>[]),
    Topic('Public-key signatures',
        description:
            'Computes a signature for a message using a secret key, and provides verification using a public key.',
        url:
            'https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures',
        samples: <Sample>[]),
    Topic('Sealed boxes',
        description:
            'Anonymously send encrypted messages to a recipient given its public key.',
        url:
            'https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes',
        samples: <Sample>[]),
    Section('Hashing'),
    Topic('Generic hashing',
        description:
            'Computes a fixed-length fingerprint for an arbitrary long message using the BLAKE2b algorithm.',
        url: 'https://libsodium.gitbook.io/doc/hashing/generic_hashing',
        samples: <Sample>[
          Sample('Usage',
              description:
                  'Computes a generic hash of predefined length and without a key for given string value.',
              name: 'generic1', func: (PrintFunc print) {
            // BEGIN generic1
            final value = 'hello world';
            final hash = GenericHash.hash(value);

            print(hex.encode(hash));
            // END generic1
          }),
          Sample('Key and outlen',
              description:
                  'Computes a generic hash of specified length for given string value and key.',
              name: 'generic2', func: (PrintFunc print) {
            // BEGIN generic2
            final value = 'hello world';
            final key = GenericHash.generateKey();
            final outlen = 16;

            final hash = GenericHash.hash(value, key: key, outlen: outlen);

            print(hex.encode(hash));
            // END generic2
          })
        ]),
    Topic('Short-input hashing',
        description: 'Computes short hashes using the SipHash-2-4 algorithm.',
        url: 'https://libsodium.gitbook.io/doc/hashing/short-input_hashing',
        samples: <Sample>[]),
    Topic('Password hashing',
        description:
            'Provides an Argon2 password hashing scheme implementation.',
        url:
            'https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function',
        samples: <Sample>[
          Sample('Hash',
              description: 'Derives a hash from given password and salt.',
              name: 'pwhash1', func: (PrintFunc print) {
            // BEGIN pwhash1
            final pw = 'hello world';
            final salt = PasswordHash.generateSalt();
            final hash = PasswordHash.hash(pw, salt);

            print(hex.encode(hash));
            // END pwhash1
          }),
          Sample('Hash storage',
              description:
                  'Computes a password verification string for given password.',
              name: 'pwhash2', func: (PrintFunc print) {
            // BEGIN pwhash2
            final pw = 'hello world';
            final str = PasswordHash.hashStorage(pw);
            print(str);

            // verify storage string
            final valid = PasswordHash.verifyStorage(str, pw);
            print('Valid: $valid');
            // END pwhash2
          }),
          Sample('Hash storage async',
              description:
                  'Execute long running hash operation in background using Flutter\'s compute.',
              name: 'pwhash3', funcAsync: (PrintFunc print) async {
            // BEGIN pwhash3
            // time operation
            final watch = Stopwatch();
            watch.start();

            // compute hash
            final pw = 'hello world';
            final str = await compute(PasswordHash.hashStorageModerate, pw);

            print(str);
            print('Compute took ${watch.elapsedMilliseconds}ms');
            watch.stop();
            // END pwhash3
          }),
        ]),
    Section('Key functions'),
    Topic('Key derivation',
        description: 'Derive secret subkeys from a single master key.',
        url: 'https://libsodium.gitbook.io/doc/key_derivation/',
        samples: <Sample>[]),
    Topic('Key exchange',
        description: 'Securely compute a set of shared keys.',
        url: 'https://libsodium.gitbook.io/doc/key_exchange/',
        samples: <Sample>[]),
    Section('Advanced'),
    Topic('Diffie-Hellman',
        description: 'Perform scalar multiplication of elliptic curve points',
        url: 'https://libsodium.gitbook.io/doc/advanced/scalar_multiplication',
        samples: <Sample>[]),
    Topic('One-time authentication',
        description: 'Secret-key single-message authentication using Poly1305',
        url: 'https://libsodium.gitbook.io/doc/advanced/poly1305',
        samples: <Sample>[]),
    Topic('Ed25519 To Curve25519 Secret Key',
        description:
            'Converts an Ed25519 Secret Key to a Curve25519 Secret Key',
        url: 'https://download.libsodium.org/doc/advanced/ed25519-curve25519',
        samples: <Sample>[])
  ];

  // load asset toc.dart for code snippets
  final src = await DefaultAssetBundle.of(context).loadString('lib/toc.dart');

  // iterate all samples in the toc, and lookup code snippet in source
  for (var topic in toc) {
    if (topic.samples != null) {
      for (var sample in topic.samples) {
        final beginTag = '// BEGIN ${sample.name}';
        final begin = src.indexOf(beginTag);
        assert(begin != -1);
        final end =
            src.indexOf('// END ${sample.name}', begin + beginTag.length);
        assert(end != -1);

        // format and assign code sample
        sample.code = _formatCode(src.substring(begin + beginTag.length, end));
      }
    }
  }

  return toc;
}

String _formatCode(String code) {
  final result = StringBuffer();
  final lines = LineSplitter.split(code).toList();
  int indent = -1;
  for (var i = 0; i < lines.length; i++) {
    String line = lines[i];
    // skip empty first and last lines
    if (line.trim().length == 0 && (i == 0 || i == lines.length - 1)) {
      continue;
    }
    // determine indent
    if (indent == -1) {
      for (indent = 0; indent < line.length; indent++) {
        if (line[indent] != ' ') {
          break;
        }
      }
    }

    // remove indent from line
    if (line.startsWith(' ' * indent)) {
      line = line.substring(indent);
    }

    if (result.isNotEmpty) {
      result.writeln();
    }
    result.write(line);
  }
  return result.toString();
}
