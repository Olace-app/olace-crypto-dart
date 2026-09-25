import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'compress/deflate.dart';
import 'offload/offload.dart';
import 'p2p_crypto.dart';
import 'recovery_key.dart';

/// Payloads/ciphertexts at or above this size run their derive + AES-GCM on a
/// worker isolate (finding #14 stage 1). 64 KiB matches
/// `_conversationMessagesEncodeOffloadBytes` in conversation_service.dart; the
/// P2P envelope path uses 96 KiB — either is fine, this reuses the conversation
/// threshold. On web `offloadCompute` runs inline (no isolates), so the gate is
/// a native-only jank fix; output is byte-identical to the inline path.
const int _zkOffloadBytes = 64 * 1024;

/// `zk1:` carries `nonce || AES-GCM(plaintext) || tag`. `zk2:` is the same
/// envelope over raw-DEFLATE-compressed plaintext, with `|zk2` appended to
/// the AAD so a prefix swapped between the two fails authentication rather
/// than handing compressed bytes to a JSON parser. Same data key.
const String _zk1Prefix = 'zk1:';
const String _zk2Prefix = 'zk2:';
const String _zk2AadSuffix = '|zk2';

/// Rough size of a JSON-able value's string content, counted only up to
/// [limit]. Decides whether encode + encrypt is worth a worker isolate
/// without paying for a full encode first.
int _estimateJsonSize(Object? value, int limit) {
  var total = 0;
  void walk(Object? v) {
    if (total >= limit) return;
    if (v is String) {
      total += v.length + 2;
    } else if (v is Map) {
      for (final entry in v.entries) {
        if (total >= limit) return;
        total += '${entry.key}'.length + 4;
        walk(entry.value);
      }
    } else if (v is List) {
      for (final item in v) {
        if (total >= limit) return;
        walk(item);
        total += 1;
      }
    } else {
      total += 8;
    }
  }

  walk(value);
  return total;
}

Future<String> _sealEnvelope(
  Uint8List mk,
  List<int> body,
  String purpose,
  String aad,
  String prefix,
) async {
  final dataKey = await ZkCrypto.deriveDataKey(mk, purpose);
  final nonce = P2PCrypto.randomBytes(12);
  final box = await AesGcm.with256bits().encrypt(
    body,
    secretKey: dataKey,
    nonce: nonce,
    aad: utf8.encode(aad),
  );
  final combined = _packEnvelope(nonce, box.cipherText, box.mac.bytes);
  return '$prefix${base64Url.encode(combined)}';
}

/// Opens a `zk1` or `zk2` envelope and returns the plaintext bytes
/// (inflated for `zk2`). Throws on format or tag failure.
Future<Uint8List> _openEnvelope(
  Uint8List mk,
  String token,
  String purpose,
  String aad,
) async {
  final compressed = token.startsWith(_zk2Prefix);
  if (!compressed && !token.startsWith(_zk1Prefix)) {
    throw const FormatException(
        'Not a ZK-encrypted payload (missing zk1:/zk2: prefix)');
  }
  final combined = base64Url.decode(token.substring(4));
  if (combined.length < 28) {
    throw const FormatException('Invalid ZK ciphertext length');
  }
  final nonce = combined.sublist(0, 12);
  final cipherText = combined.sublist(12, combined.length - 16);
  final tag = combined.sublist(combined.length - 16);
  final dataKey = await ZkCrypto.deriveDataKey(mk, purpose);
  final cleartext = await AesGcm.with256bits().decrypt(
    SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
    secretKey: dataKey,
    aad: utf8.encode(compressed ? '$aad$_zk2AadSuffix' : aad),
  );
  return compressed ? inflateRaw(cleartext) : _asUint8List(cleartext);
}

Future<({String token, int plaintextBytes})> _encryptJsonInline(
  Uint8List mk,
  Map<String, dynamic> payload,
  String purpose,
  String aad,
  bool compress,
) async {
  final plaintext = utf8.encode(jsonEncode(payload));
  final token = compress
      ? await _sealEnvelope(
          mk, deflateRaw(plaintext), purpose, '$aad$_zk2AadSuffix', _zk2Prefix)
      : await _sealEnvelope(mk, plaintext, purpose, aad, _zk1Prefix);
  return (token: token, plaintextBytes: plaintext.length);
}

Future<Map<String, dynamic>> _decryptJsonInline(
  Uint8List mk,
  String token,
  String purpose,
  String aad,
) async {
  final cleartext = await _openEnvelope(mk, token, purpose, aad);
  return jsonDecode(utf8.decode(cleartext)) as Map<String, dynamic>;
}

Future<({String token, int plaintextBytes})> _encryptJsonWorker(
  Map<String, dynamic> args,
) =>
    _encryptJsonInline(
      args['mk'] as Uint8List,
      args['payload'] as Map<String, dynamic>,
      args['purpose'] as String,
      args['aad'] as String,
      args['compress'] as bool,
    );

Future<Map<String, dynamic>> _decryptJsonWorker(Map<String, dynamic> args) =>
    _decryptJsonInline(
      args['mk'] as Uint8List,
      args['token'] as String,
      args['purpose'] as String,
      args['aad'] as String,
    );

// ── Offload workers (finding #14 stage 1) ───────────────────────────
// Top-level so Isolate.run can send them with no closure capture, mirroring
// P2PCrypto._encryptP2PEnvelopeWorker. HKDF/AesGcm re-initialise in the worker
// isolate; the MK bytes are passed in-memory (same process — no persistence,
// no network), exactly as the P2P path passes session-key bytes. Byte output
// is identical to the inline methods below.

/// Pack `nonce || ciphertext || tag` without the `[...a, ...b, ...c]`
/// spread — on dart2js a spread over a multi-MB ciphertext builds a boxed
/// JSArray element-by-element before copying, two extra O(n) passes on the
/// main thread.
Uint8List _packEnvelope(
  List<int> nonce,
  List<int> cipherText,
  List<int> mac,
) {
  final out = Uint8List(nonce.length + cipherText.length + mac.length);
  out.setRange(0, nonce.length, nonce);
  out.setRange(nonce.length, nonce.length + cipherText.length, cipherText);
  out.setRange(nonce.length + cipherText.length, out.length, mac);
  return out;
}

Uint8List _asUint8List(List<int> bytes) =>
    bytes is Uint8List ? bytes : Uint8List.fromList(bytes);

Future<String> _zkEncryptWithMkWorker(Map<String, dynamic> args) async {
  final mk = args['mk'] as Uint8List;
  final plaintext = args['plaintext'] as Uint8List;
  final purpose = args['purpose'] as String;
  final aad = args['aad'] as String;
  final dataKey = await ZkCrypto.deriveDataKey(mk, purpose);
  final nonce = P2PCrypto.randomBytes(12);
  final box = await AesGcm.with256bits().encrypt(
    plaintext,
    secretKey: dataKey,
    nonce: nonce,
    aad: utf8.encode(aad),
  );
  final combined = _packEnvelope(nonce, box.cipherText, box.mac.bytes);
  return 'zk1:${base64Url.encode(combined)}';
}

Future<Uint8List> _zkDecryptWithMkWorker(Map<String, dynamic> args) =>
    _openEnvelope(
      args['mk'] as Uint8List,
      args['token'] as String,
      args['purpose'] as String,
      args['aad'] as String,
    );

Future<Uint8List> _zkEncryptMediaBlobWorker(Map<String, dynamic> args) async {
  final mk = args['mk'] as Uint8List;
  final cleartext = args['cleartext'] as Uint8List;
  final purpose = args['purpose'] as String;
  final aad = args['aad'] as String;
  final dataKey = await ZkCrypto.deriveDataKey(mk, purpose);
  final nonce = P2PCrypto.randomBytes(12);
  final box = await AesGcm.with256bits().encrypt(
    cleartext,
    secretKey: dataKey,
    nonce: nonce,
    aad: utf8.encode(aad),
  );
  return _packEnvelope(nonce, box.cipherText, box.mac.bytes);
}

Future<Uint8List> _zkDecryptMediaBlobWorker(Map<String, dynamic> args) async {
  final mk = args['mk'] as Uint8List;
  final encrypted = args['encrypted'] as Uint8List;
  final purpose = args['purpose'] as String;
  final aad = args['aad'] as String;
  final nonce = encrypted.sublist(0, 12);
  final cipherText = encrypted.sublist(12, encrypted.length - 16);
  final tag = encrypted.sublist(encrypted.length - 16);
  final dataKey = await ZkCrypto.deriveDataKey(mk, purpose);
  final cleartext = await AesGcm.with256bits().decrypt(
    SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
    secretKey: dataKey,
    aad: utf8.encode(aad),
  );
  return _asUint8List(cleartext);
}

/// Stateless zero-knowledge encryption core.
///
/// All user content (conversations, media) is encrypted with a Master Key
/// (MK) that the server never sees. The MK is wrapped with a key derived
/// from the user's Recovery Key and stored on the server as an opaque
/// blob. Every method takes the MK as a parameter: this package derives
/// and transforms keys, it never holds them.
class ZkCrypto {
  ZkCrypto._();

  static final AesGcm _aesGcm = AesGcm.with256bits();
  static final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  // ── Key generation ──────────────────────────────────────────

  /// Generate a fresh Master Key and Recovery Key.
  ///
  /// Returns `(mk: raw 32 bytes, recoveryKey: formatted string)`.
  static ({Uint8List mk, String recoveryKey, Uint8List recoveryKeyBytes})
      generateKeys() {
    final mk = P2PCrypto.randomBytes(32);
    final recoveryKeyBytes = P2PCrypto.randomBytes(16);
    final recoveryKey = RecoveryKey.format(recoveryKeyBytes);
    return (
      mk: mk,
      recoveryKey: recoveryKey,
      recoveryKeyBytes: recoveryKeyBytes
    );
  }

  // ── Key wrapping ────────────────────────────────────────────

  /// Wrap the MK with a key derived from the Recovery Key.
  ///
  /// Returns base64url-encoded `nonce || ciphertext || tag`.
  static Future<String> wrapMk(
    Uint8List mk,
    Uint8List recoveryKeyBytes,
    String userId,
  ) async {
    final wrappingKey = await _deriveWrappingKey(recoveryKeyBytes, userId);
    final nonce = P2PCrypto.randomBytes(12);
    final aad = utf8.encode('olace-mk-wrap-v1|$userId');
    final box = await _aesGcm.encrypt(
      mk,
      secretKey: wrappingKey,
      nonce: nonce,
      aad: aad,
    );
    // nonce(12) + ciphertext + mac(16)
    final combined = _packEnvelope(nonce, box.cipherText, box.mac.bytes);
    return base64Url.encode(combined);
  }

  /// Unwrap the MK using the Recovery Key.
  ///
  /// Throws on wrong key (GCM auth failure).
  static Future<Uint8List> unwrapMk(
    String wrappedMkB64,
    Uint8List recoveryKeyBytes,
    String userId,
  ) async {
    final wrappingKey = await _deriveWrappingKey(recoveryKeyBytes, userId);
    final combined = base64Url.decode(wrappedMkB64);
    if (combined.length < 28) {
      throw const FormatException('Invalid wrapped key length');
    }
    final nonce = combined.sublist(0, 12);
    final cipherText = combined.sublist(12, combined.length - 16);
    final tag = combined.sublist(combined.length - 16);
    final aad = utf8.encode('olace-mk-wrap-v1|$userId');
    final cleartext = await _aesGcm.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
      secretKey: wrappingKey,
      aad: aad,
    );
    return _asUint8List(cleartext);
  }

  static Future<SecretKey> _deriveWrappingKey(
    Uint8List recoveryKeyBytes,
    String userId,
  ) async {
    return _hkdf.deriveKey(
      secretKey: SecretKey(recoveryKeyBytes),
      nonce: utf8.encode('olace-zk-recovery-v1'),
      info: utf8.encode('mk-wrap|$userId'),
    );
  }

  // ── Data encryption / decryption ────────────────────────────

  /// Encrypt a conversation payload.
  ///
  /// Returns `"zk1:" + base64url(nonce + ciphertext + tag)`, or the `zk2:`
  /// compressed envelope when [compress] is set.
  static Future<String> encryptConversation(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String userId,
    required String conversationId,
    bool compress = false,
  }) async =>
      (await encryptConversationSized(
        mk,
        payload,
        userId: userId,
        conversationId: conversationId,
        compress: compress,
      ))
          .token;

  /// [encryptConversation], also returning the UTF-8 JSON plaintext length
  /// so a caller that reports the size does not encode the payload twice.
  static Future<({String token, int plaintextBytes})> encryptConversationSized(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String userId,
    required String conversationId,
    bool compress = false,
  }) {
    final purpose = 'conv|$userId|$conversationId';
    return encryptJson(mk, payload,
        purpose: purpose, aad: purpose, compress: compress);
  }

  /// Decrypt a conversation payload (`zk1` or `zk2`).
  static Future<Map<String, dynamic>> decryptConversation(
    Uint8List mk,
    String ciphertext, {
    required String userId,
    required String conversationId,
  }) {
    final purpose = 'conv|$userId|$conversationId';
    return decryptJson(mk, ciphertext, purpose: purpose, aad: purpose);
  }

  /// Encrypt a project payload.
  ///
  /// Returns `"zk1:" + base64url(nonce + ciphertext + tag)`, or the `zk2:`
  /// compressed envelope when [compress] is set.
  static Future<String> encryptProject(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String userId,
    required String projectId,
    bool compress = false,
  }) async {
    final purpose = 'proj|$userId|$projectId';
    return (await encryptJson(mk, payload,
            purpose: purpose, aad: purpose, compress: compress))
        .token;
  }

  /// Decrypt a project payload (`zk1` or `zk2`).
  static Future<Map<String, dynamic>> decryptProject(
    Uint8List mk,
    String ciphertext, {
    required String userId,
    required String projectId,
  }) {
    final purpose = 'proj|$userId|$projectId';
    return decryptJson(mk, ciphertext, purpose: purpose, aad: purpose);
  }

  /// Encrypt research context payload (conversation-scoped).
  static Future<String> encryptResearchContext(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String userId,
    required String conversationId,
    bool compress = false,
  }) async {
    final purpose = 'rctx|$userId|$conversationId';
    return (await encryptJson(mk, payload,
            purpose: purpose, aad: purpose, compress: compress))
        .token;
  }

  /// Decrypt research context payload (`zk1` or `zk2`).
  static Future<Map<String, dynamic>> decryptResearchContext(
    Uint8List mk,
    String ciphertext, {
    required String userId,
    required String conversationId,
  }) {
    final purpose = 'rctx|$userId|$conversationId';
    return decryptJson(mk, ciphertext, purpose: purpose, aad: purpose);
  }

  /// Encrypt a JSON payload into a `zk1` envelope, or with [compress] a
  /// `zk2` one (raw DEFLATE before AES-GCM). JSON encode, compression and
  /// encryption run together on a worker isolate once the payload is large
  /// enough to stall the caller; the bytes are identical either way.
  static Future<({String token, int plaintextBytes})> encryptJson(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String purpose,
    required String aad,
    bool compress = false,
  }) {
    if (_estimateJsonSize(payload, _zkOffloadBytes) >= _zkOffloadBytes) {
      return offloadCompute(_encryptJsonWorker, {
        'mk': mk,
        'payload': payload,
        'purpose': purpose,
        'aad': aad,
        'compress': compress,
      });
    }
    return _encryptJsonInline(mk, payload, purpose, aad, compress);
  }

  /// Decrypt a `zk1` or `zk2` envelope and parse its JSON. Large tokens are
  /// decrypted, inflated and parsed on a worker isolate.
  static Future<Map<String, dynamic>> decryptJson(
    Uint8List mk,
    String token, {
    required String purpose,
    required String aad,
  }) {
    if (token.length >= _zkOffloadBytes) {
      return offloadCompute(_decryptJsonWorker, {
        'mk': mk,
        'token': token,
        'purpose': purpose,
        'aad': aad,
      });
    }
    return _decryptJsonInline(mk, token, purpose, aad);
  }

  /// Encrypt the user-instructions backup payload.
  ///
  /// Returns `"zk1:" + base64url(nonce + ciphertext + tag)`.
  static Future<String> encryptInstructions(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String userId,
  }) async {
    final purpose = 'instr|$userId';
    final aad = purpose;
    final plaintext = utf8.encode(jsonEncode(payload));
    return encryptWithMk(mk, plaintext, purpose, aad);
  }

  /// Decrypt a user-instructions backup payload.
  static Future<Map<String, dynamic>> decryptInstructions(
    Uint8List mk,
    String ciphertext, {
    required String userId,
  }) async {
    final purpose = 'instr|$userId';
    final aad = purpose;
    final cleartext = await decryptWithMk(mk, ciphertext, purpose, aad);
    return jsonDecode(utf8.decode(cleartext)) as Map<String, dynamic>;
  }

  /// Encrypt the BYOK key vault. One ciphertext blob per user holding
  /// every configured provider's key — the server cannot infer which
  /// providers a user has set up because the entire map is opaque.
  ///
  /// Returns ``"zk1:" + base64url(nonce + ciphertext + tag)``.
  static Future<String> encryptByokVault(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String userId,
  }) async {
    final purpose = 'byok_vault|$userId';
    final aad = purpose;
    final plaintext = utf8.encode(jsonEncode(payload));
    return encryptWithMk(mk, plaintext, purpose, aad);
  }

  /// Decrypt a BYOK vault ciphertext into the JSON payload.
  static Future<Map<String, dynamic>> decryptByokVault(
    Uint8List mk,
    String ciphertext, {
    required String userId,
  }) async {
    final purpose = 'byok_vault|$userId';
    final aad = purpose;
    final cleartext = await decryptWithMk(mk, ciphertext, purpose, aad);
    return jsonDecode(utf8.decode(cleartext)) as Map<String, dynamic>;
  }

  /// Encrypt a media blob. Returns `nonce + ciphertext + tag` as bytes.
  static Future<Uint8List> encryptMediaBlob(
    Uint8List mk,
    Uint8List cleartext, {
    required String userId,
    required String attachmentId,
  }) async {
    final purpose = 'media|$userId|$attachmentId';
    final aad = purpose;
    if (cleartext.length >= _zkOffloadBytes) {
      return offloadCompute(_zkEncryptMediaBlobWorker, {
        'mk': mk,
        'cleartext': cleartext,
        'purpose': purpose,
        'aad': aad,
      });
    }
    final dataKey = await deriveDataKey(mk, purpose);
    final nonce = P2PCrypto.randomBytes(12);
    final box = await _aesGcm.encrypt(
      cleartext,
      secretKey: dataKey,
      nonce: nonce,
      aad: utf8.encode(aad),
    );
    return _packEnvelope(nonce, box.cipherText, box.mac.bytes);
  }

  /// Decrypt a media blob.
  static Future<Uint8List> decryptMediaBlob(
    Uint8List mk,
    Uint8List encrypted, {
    required String userId,
    required String attachmentId,
  }) async {
    final purpose = 'media|$userId|$attachmentId';
    final aad = purpose;
    if (encrypted.length < 28) {
      throw const FormatException('Invalid encrypted media length');
    }
    if (encrypted.length >= _zkOffloadBytes) {
      return offloadCompute(_zkDecryptMediaBlobWorker, {
        'mk': mk,
        'encrypted': encrypted,
        'purpose': purpose,
        'aad': aad,
      });
    }
    final dataKey = await deriveDataKey(mk, purpose);
    final nonce = encrypted.sublist(0, 12);
    final cipherText = encrypted.sublist(12, encrypted.length - 16);
    final tag = encrypted.sublist(encrypted.length - 16);
    final cleartext = await _aesGcm.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
      secretKey: dataKey,
      aad: utf8.encode(aad),
    );
    return _asUint8List(cleartext);
  }

  /// Encrypt a short metadata string (e.g. file_name, mime_type) tied to a
  /// specific attachment. Reuses the per-attachment data key, but binds
  /// `field` into the AAD so a ciphertext minted for one field can never
  /// be replayed as another (e.g. file_name ciphertext won't decrypt in
  /// mime_type context). Output: base64url of nonce || ct || tag.
  static Future<String> encryptAttachmentMetadata(
    Uint8List mk,
    String plaintext, {
    required String userId,
    required String attachmentId,
    required String field,
  }) async {
    final purpose = 'media|$userId|$attachmentId';
    final aad = 'media-meta|$userId|$attachmentId|$field';
    final dataKey = await deriveDataKey(mk, purpose);
    final nonce = P2PCrypto.randomBytes(12);
    final box = await _aesGcm.encrypt(
      utf8.encode(plaintext),
      secretKey: dataKey,
      nonce: nonce,
      aad: utf8.encode(aad),
    );
    final combined = _packEnvelope(nonce, box.cipherText, box.mac.bytes);
    return base64Url.encode(combined);
  }

  /// Inverse of [encryptAttachmentMetadata]. Throws on tag mismatch (wrong
  /// key, wrong AAD, or tampered ciphertext).
  static Future<String> decryptAttachmentMetadata(
    Uint8List mk,
    String b64, {
    required String userId,
    required String attachmentId,
    required String field,
  }) async {
    final purpose = 'media|$userId|$attachmentId';
    final aad = 'media-meta|$userId|$attachmentId|$field';
    final dataKey = await deriveDataKey(mk, purpose);
    final combined = base64Url.decode(b64);
    if (combined.length < 28) {
      throw const FormatException('Invalid encrypted metadata length');
    }
    final nonce = combined.sublist(0, 12);
    final cipherText = combined.sublist(12, combined.length - 16);
    final tag = combined.sublist(combined.length - 16);
    final cleartext = await _aesGcm.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
      secretKey: dataKey,
      aad: utf8.encode(aad),
    );
    return utf8.decode(cleartext);
  }

  // ── Envelope primitives ─────────────────────────────────────

  /// Encrypt bytes under a per-purpose data key derived from the MK.
  /// Output format is the `zk1` envelope:
  /// `"zk1:" + base64url(nonce(12) || ciphertext || tag(16))`.
  static Future<String> encryptWithMk(
    Uint8List mk,
    List<int> plaintext,
    String purpose,
    String aad,
  ) async {
    if (plaintext.length >= _zkOffloadBytes) {
      return offloadCompute(_zkEncryptWithMkWorker, {
        'mk': mk,
        'plaintext':
            plaintext is Uint8List ? plaintext : Uint8List.fromList(plaintext),
        'purpose': purpose,
        'aad': aad,
      });
    }
    final dataKey = await deriveDataKey(mk, purpose);
    final nonce = P2PCrypto.randomBytes(12);
    final box = await _aesGcm.encrypt(
      plaintext,
      secretKey: dataKey,
      nonce: nonce,
      aad: utf8.encode(aad),
    );
    final combined = _packEnvelope(nonce, box.cipherText, box.mac.bytes);
    return 'zk1:${base64Url.encode(combined)}';
  }

  /// Decrypt a `zk1` envelope, or a `zk2` one (returned inflated). Throws
  /// on format or tag failure.
  static Future<Uint8List> decryptWithMk(
    Uint8List mk,
    String token,
    String purpose,
    String aad,
  ) async {
    if (!token.startsWith(_zk1Prefix) && !token.startsWith(_zk2Prefix)) {
      throw const FormatException(
          'Not a ZK-encrypted payload (missing zk1:/zk2: prefix)');
    }
    if (token.length >= _zkOffloadBytes) {
      return offloadCompute(_zkDecryptWithMkWorker, {
        'mk': mk,
        'token': token,
        'purpose': purpose,
        'aad': aad,
      });
    }
    return _openEnvelope(mk, token, purpose, aad);
  }

  /// Per-purpose data key: HKDF-SHA256 over the MK with salt
  /// `olace-zk-data-v1` and the purpose string as info. Purposes are
  /// namespaced per data class and id (`conv|user|id`, `media|user|id`,
  /// ...), so no two objects ever share an AES key.
  static Future<SecretKey> deriveDataKey(Uint8List mk, String purpose) async {
    return _hkdf.deriveKey(
      secretKey: SecretKey(mk),
      nonce: utf8.encode('olace-zk-data-v1'),
      info: utf8.encode(purpose),
    );
  }

  // ── MK possession proof ─────────────────────────────────────────────
  //
  // The account's MK-derived identity keypair: an Ed25519 seed HKDF'd from
  // the MK (salt `olace-mk-proof-v1`, info = userId), so any device holding
  // the MK derives the SAME keypair deterministically and the public key
  // can be registered server-side as a possession verifier. The server can
  // only verify signatures, never the derivation, which is why step-up
  // additionally age-gates a registered key.

  static final Ed25519 _ed25519 = Ed25519();

  static String _b64urlNoPad(List<int> raw) =>
      base64Url.encode(raw).replaceAll('=', '');

  /// The account's deterministic MK-derived Ed25519 keypair (see the
  /// section comment above for the derivation and why it exists).
  static Future<SimpleKeyPair> deriveMkProofKeyPair(
    Uint8List mk,
    String userId,
  ) async {
    final seedKey = await _hkdf.deriveKey(
      secretKey: SecretKey(mk),
      nonce: utf8.encode('olace-mk-proof-v1'),
      info: utf8.encode(userId),
    );
    final seed = await seedKey.extractBytes();
    return _ed25519.newKeyPairFromSeed(seed);
  }

  /// b64url (unpadded) raw 32-byte Ed25519 public key, the value registered
  /// via POST /sync/encryption/mk-proof/register.
  static Future<String> mkProofPublicKeyB64(Uint8List mk, String userId) async {
    final keyPair = await deriveMkProofKeyPair(mk, userId);
    final publicKey = await keyPair.extractPublicKey();
    return _b64urlNoPad(publicKey.bytes);
  }

  /// Signature over the canonical challenge message, b64url unpadded.
  /// The message shape is byte-identical to the backend verifier
  /// (`mk_proof_message` in phone_auth_flow_recovery.py):
  /// `olace-mk-proof-v1|{userId}|{purpose}|{nonce}`.
  static Future<String> signMkProofChallenge({
    required Uint8List mk,
    required String userId,
    required String purpose,
    required String nonce,
  }) async {
    final keyPair = await deriveMkProofKeyPair(mk, userId);
    final message = utf8.encode('olace-mk-proof-v1|$userId|$purpose|$nonce');
    final signature = await _ed25519.sign(message, keyPair: keyPair);
    return _b64urlNoPad(signature.bytes);
  }
}
