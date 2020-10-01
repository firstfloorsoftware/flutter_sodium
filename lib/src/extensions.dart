import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'sodium_exception.dart';

extension Uint8Pointer on Pointer<Uint8> {
  Uint8List toList(int length) {
    final builder = BytesBuilder();
    for (var i = 0; i < length; i++) {
      builder.addByte(this[i]);
    }
    return builder.takeBytes();
  }

  Uint8List toNullTerminatedList(int maxLength) {
    final builder = BytesBuilder();
    for (var i = 0; i < maxLength; i++) {
      builder.addByte(this[i]);
      if (this[i] == 0) {
        break;
      }
    }
    return builder.takeBytes();
  }
}

extension Uint8ListExtensions on Uint8List {
  Pointer<Uint8> toPointer() {
    if (this == null) {
      return Pointer<Uint8>.fromAddress(0);
    }
    final p = allocate<Uint8>(count: this.length);
    p.asTypedList(this.length).setAll(0, this);
    return p;
  }
}

extension Result on int {
  void mustSucceed(String funcName) {
    if (this != 0) {
      throw SodiumException('$funcName failed with $this');
    }
  }
}
