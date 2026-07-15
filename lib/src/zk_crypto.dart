import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

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

// ── Offload workers (finding #14 stage 1) ───────────────────────────
// Top-level so Isolate.run can send them with no closure capture, mirroring
// P2PCrypto._encryptP2PEnvelopeWorker. HKDF/AesGcm re-initialise in the worker
// isolate; the MK bytes are passed in-memory (same process — no persistence,
// no network), exactly as the P2P path passes session-key bytes. Byte output
// is identical to the inline methods below.

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
  final combined = Uint8List.fromList([
    ...nonce,
    ...box.cipherText,
    ...box.mac.bytes,
  ]);
  return 'zk1:${base64Url.encode(combined)}';
}

Future<Uint8List> _zkDecryptWithMkWorker(Map<String, dynamic> args) async {
  final mk = args['mk'] as Uint8List;
  final token = args['token'] as String;
  final purpose = args['purpose'] as String;
  final aad = args['aad'] as String;
  final b64 = token.substring(4); // caller validated the 'zk1:' prefix
  final combined = base64Url.decode(b64);
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
    aad: utf8.encode(aad),
  );
  return Uint8List.fromList(cleartext);
}

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
  return Uint8List.fromList([...nonce, ...box.cipherText, ...box.mac.bytes]);
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
  return Uint8List.fromList(cleartext);
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
    final combined = Uint8List.fromList([
      ...nonce,
      ...box.cipherText,
      ...box.mac.bytes,
    ]);
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
    return Uint8List.fromList(cleartext);
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
  /// Returns `"zk1:" + base64url(nonce + ciphertext + tag)`.
  static Future<String> encryptConversation(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String userId,
    required String conversationId,
  }) async {
    final purpose = 'conv|$userId|$conversationId';
    final aad = purpose;
    final plaintext = utf8.encode(jsonEncode(payload));
    return encryptWithMk(mk, plaintext, purpose, aad);
  }

  /// Decrypt a conversation payload.
  static Future<Map<String, dynamic>> decryptConversation(
    Uint8List mk,
    String ciphertext, {
    required String userId,
    required String conversationId,
  }) async {
    final purpose = 'conv|$userId|$conversationId';
    final aad = purpose;
    final cleartext = await decryptWithMk(mk, ciphertext, purpose, aad);
    return jsonDecode(utf8.decode(cleartext)) as Map<String, dynamic>;
  }

  /// Encrypt a project payload.
  ///
  /// Returns `"zk1:" + base64url(nonce + ciphertext + tag)`.
  static Future<String> encryptProject(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String userId,
    required String projectId,
  }) async {
    final purpose = 'proj|$userId|$projectId';
    final aad = purpose;
    final plaintext = utf8.encode(jsonEncode(payload));
    return encryptWithMk(mk, plaintext, purpose, aad);
  }

  /// Decrypt a project payload.
  static Future<Map<String, dynamic>> decryptProject(
    Uint8List mk,
    String ciphertext, {
    required String userId,
    required String projectId,
  }) async {
    final purpose = 'proj|$userId|$projectId';
    final aad = purpose;
    final cleartext = await decryptWithMk(mk, ciphertext, purpose, aad);
    return jsonDecode(utf8.decode(cleartext)) as Map<String, dynamic>;
  }

  /// Encrypt research context payload (conversation-scoped).
  static Future<String> encryptResearchContext(
    Uint8List mk,
    Map<String, dynamic> payload, {
    required String userId,
    required String conversationId,
  }) async {
    final purpose = 'rctx|$userId|$conversationId';
    final aad = purpose;
    final plaintext = utf8.encode(jsonEncode(payload));
    return encryptWithMk(mk, plaintext, purpose, aad);
  }

  /// Decrypt research context payload.
  static Future<Map<String, dynamic>> decryptResearchContext(
    Uint8List mk,
    String ciphertext, {
    required String userId,
    required String conversationId,
  }) async {
    final purpose = 'rctx|$userId|$conversationId';
    final aad = purpose;
    final cleartext = await decryptWithMk(mk, ciphertext, purpose, aad);
    return jsonDecode(utf8.decode(cleartext)) as Map<String, dynamic>;
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
    return Uint8List.fromList([...nonce, ...box.cipherText, ...box.mac.bytes]);
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
    return Uint8List.fromList(cleartext);
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
    final combined = Uint8List.fromList([
      ...nonce,
      ...box.cipherText,
      ...box.mac.bytes,
    ]);
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
    final combined = Uint8List.fromList([
      ...nonce,
      ...box.cipherText,
      ...box.mac.bytes,
    ]);
    return 'zk1:${base64Url.encode(combined)}';
  }

  /// Decrypt a `zk1` envelope. Throws on format or tag failure.
  static Future<Uint8List> decryptWithMk(
    Uint8List mk,
    String token,
    String purpose,
    String aad,
  ) async {
    if (!token.startsWith('zk1:')) {
      throw const FormatException(
          'Not a ZK-encrypted payload (missing zk1: prefix)');
    }
    if (token.length >= _zkOffloadBytes) {
      return offloadCompute(_zkDecryptWithMkWorker, {
        'mk': mk,
        'token': token,
        'purpose': purpose,
        'aad': aad,
      });
    }
    final b64 = token.substring(4);
    final combined = base64Url.decode(b64);
    if (combined.length < 28) {
      throw const FormatException('Invalid ZK ciphertext length');
    }
    final nonce = combined.sublist(0, 12);
    final cipherText = combined.sublist(12, combined.length - 16);
    final tag = combined.sublist(combined.length - 16);
    final dataKey = await deriveDataKey(mk, purpose);
    final cleartext = await _aesGcm.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
      secretKey: dataKey,
      aad: utf8.encode(aad),
    );
    return Uint8List.fromList(cleartext);
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
}
