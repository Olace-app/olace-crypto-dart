import 'dart:typed_data';

import 'package:archive/archive.dart' show Deflate, Inflate;

/// Raw DEFLATE (no zlib header) of [bytes].
Uint8List deflateRaw(List<int> bytes) =>
    Uint8List.fromList(Deflate(bytes, level: 6).getBytes());

/// Inverse of [deflateRaw].
Uint8List inflateRaw(List<int> bytes) =>
    Uint8List.fromList(Inflate(bytes).getBytes());
