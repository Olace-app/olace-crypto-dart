import 'dart:io' show ZLibCodec;
import 'dart:typed_data';

final ZLibCodec _rawDeflate = ZLibCodec(raw: true, level: 6);

/// Raw DEFLATE (no zlib header) of [bytes].
Uint8List deflateRaw(List<int> bytes) =>
    Uint8List.fromList(_rawDeflate.encode(bytes));

/// Inverse of [deflateRaw].
Uint8List inflateRaw(List<int> bytes) =>
    Uint8List.fromList(_rawDeflate.decode(bytes));
