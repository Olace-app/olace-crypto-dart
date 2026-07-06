import 'dart:typed_data';

/// Crockford Base32 alphabet (no I, L, O, U — avoids ambiguity).
const _crockfordAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/// Recovery Key formatting: 16 random bytes shown to the user as
/// Crockford Base32 in dash-separated groups.
class RecoveryKey {
  RecoveryKey._();

  /// Encode 16 bytes as Crockford Base32 grouped with dashes.
  ///
  /// Format: `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X` (128 bits → 26 chars).
  static String format(Uint8List bytes) {
    final encoded = _crockfordBase32Encode(bytes);
    final buf = StringBuffer();
    for (var i = 0; i < encoded.length; i++) {
      if (i > 0 && i % 5 == 0) buf.write('-');
      buf.write(encoded[i]);
    }
    return buf.toString();
  }

  /// Parse a formatted Recovery Key back to bytes.
  ///
  /// Strips dashes/spaces, normalizes case, returns null on invalid input.
  static Uint8List? parse(String formatted) {
    final cleaned = formatted
        .replaceAll(RegExp(r'[\s\-]'), '')
        .toUpperCase()
        // Crockford normalization: O→0, I/L→1
        .replaceAll('O', '0')
        .replaceAll('I', '1')
        .replaceAll('L', '1');
    if (cleaned.isEmpty) return null;
    try {
      return _crockfordBase32Decode(cleaned);
    } catch (_) {
      return null;
    }
  }

  static String _crockfordBase32Encode(Uint8List data) {
    final buf = StringBuffer();
    var bitBuffer = 0;
    var bitsInBuffer = 0;
    for (final byte in data) {
      bitBuffer = (bitBuffer << 8) | byte;
      bitsInBuffer += 8;
      while (bitsInBuffer >= 5) {
        bitsInBuffer -= 5;
        buf.write(_crockfordAlphabet[(bitBuffer >> bitsInBuffer) & 0x1F]);
      }
    }
    if (bitsInBuffer > 0) {
      buf.write(
        _crockfordAlphabet[(bitBuffer << (5 - bitsInBuffer)) & 0x1F],
      );
    }
    return buf.toString();
  }

  static Uint8List _crockfordBase32Decode(String encoded) {
    var bitBuffer = 0;
    var bitsInBuffer = 0;
    final bytes = <int>[];
    for (final char in encoded.split('')) {
      final idx = _crockfordAlphabet.indexOf(char);
      if (idx < 0) throw FormatException('Invalid base32 character: $char');
      bitBuffer = (bitBuffer << 5) | idx;
      bitsInBuffer += 5;
      if (bitsInBuffer >= 8) {
        bitsInBuffer -= 8;
        bytes.add((bitBuffer >> bitsInBuffer) & 0xFF);
      }
    }
    // Reject non-canonical encodings: trailing padding bits must be zero.
    if (bitsInBuffer > 0) {
      final paddingBits = bitBuffer & ((1 << bitsInBuffer) - 1);
      if (paddingBits != 0) {
        throw const FormatException('Invalid base32 padding');
      }
    }
    return Uint8List.fromList(bytes);
  }
}
