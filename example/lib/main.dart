import 'package:flutter/material.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'package:convert/convert.dart';
import 'dart:async';
import 'example.dart';
import 'sample.dart';

void main() => runApp(new MyApp());

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(home: HomePage());
  }
}

class HomePage extends StatelessWidget {
  final _examples = [
    Example('Common', isHeader: true),
    Example('Random data',
        description:
            'Provides a set of functions to generate unpredictable data, suitable for creating secret keys.',
        docUrl: 'https://download.libsodium.org/doc/generating_random_data/',
        samples: [
          Sample(
              'Random',
              'Returns an unpredictable value between 0 and 0xffffffff (included)',
              '''final rnd = await Randombytes.random();
print(rnd);''', () async {
            final rnd = await Randombytes.random();
            return rnd.toString();
          }),
          Sample(
              'Uniform',
              'Generates an unpredictable value between 0 and upperBound (excluded)',
              '''final rnd = await Randombytes.uniform(16);
print(rnd);''', () async {
            final rnd = await Randombytes.uniform(16);
            return rnd.toString();
          }),
          Sample(
              'Buffer',
              'Generates an unpredictable sequence of bytes of specified size.',
              '''final buffer = await Randombytes.buffer(16);
print(hex.encode(buffer));''', () async {
            final buffer = await Randombytes.buffer(16);
            return hex.encode(buffer);
          })
        ]),
    // Example('Secret-key cryptography', isHeader: true),
    // Example('Authenticated encryption'),
    // Example('Authentication'),
    // Example('Public-key cryptography', isHeader: true),
    // Example('Authenticated encryption'),
    // Example('Public-key signatures'),
    // Example('Sealed boxes'),
    Example('Hashing', isHeader: true),
    Example('Generic hashing',
        description:
            'Computes a fixed-length fingerprint for an arbitrary long message using the BLAKE2b algorithm.',
        docUrl:
            'https://download.libsodium.org/doc/hashing/generic_hashing.html',
        samples: [
          Sample(
              'Hash string',
              'Computes a generic hash of specified length for given string value and optional key.',
              '''var value = 'hello world';
var hash = await GenericHash.hashString(value);

print(hex.encode(hash));''', () async {
            var value = 'hello world';
            var hash = await GenericHash.hashString(value);

            return hex.encode(hash);
          })
        ]),
    Example('Short-input hashing',
        description: 'Computes short hashes using the SipHash-2-4 algorithm.',
        docUrl:
            'https://download.libsodium.org/doc/hashing/short-input_hashing.html',
        samples: [
          Sample(
              'Hash string',
              'Computes a fixed-size fingerprint for given string value and key.',
              '''var value = 'hello world';
var key = await ShortHash.generateKey();
var hash = await ShortHash.hashString(value, key);

print(hex.encode(hash));''', () async {
            var value = 'hello world';
            var key = await ShortHash.generateKey();
            var hash = await ShortHash.hashString(value, key);

            return hex.encode(hash);
          })
        ]),
    Example('Password hashing',
        description:
            'Provides an Argon2 password hashing scheme implementation.',
        docUrl:
            'https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html',
        samples: [
          Sample('Hash', 'Derives a hash from given password and salt.',
              '''var pw = 'hello world';
var salt = await PasswordHash.generateSalt();
var hash = await PasswordHash.hash(pw, salt);

print(hex.encode(hash));''', () async {
            var pwd = 'hello world';
            var salt = await PasswordHash.generateSalt();
            var hash = await PasswordHash.hash(pwd, salt);
            return hex.encode(hash);
          }),
          Sample(
              'Hash storage',
              'Computes a password verification string for given password.',
              '''var pw = 'hello world';
var str = await PasswordHash.hashStorage(pw);

print(str);

// verify storage string
var valid = await PasswordHash.verifyStorage(str, pw);''', () async {
            var pwd = 'hello world';
            return await PasswordHash.hashStorage(pwd);
          })
        ]),
    // Example('Key functions', isHeader: true),
    // Example('Key derivation'),
    // Example('Key exchange'),
    // Example('Advanced', isHeader: true),
    // Example('Diffie-Hellman'),
    // Example('One-time authentication'),
  ];

  Widget _buildListTile(BuildContext context, Example example) {
    if (example.isHeader) {
      var color = Theme.of(context).primaryColor;
      return ListTile(
          title: Text(example.title,
              style: Theme.of(context).textTheme.title.apply(color: color)));
    } else {
      return ListTile(
          title: Text(example.title),
          trailing: Icon(Icons.arrow_forward_ios, size: 12.0),
          onTap: () => example.navigate(context));
    }
  }

  @override
  Widget build(BuildContext context) {
    return new Scaffold(
        appBar: new AppBar(
          title: new Text("Flutter Sodium"),
        ),
        body: ListView(
            children:
                _examples.map((e) => _buildListTile(context, e)).toList()));
  }
}
