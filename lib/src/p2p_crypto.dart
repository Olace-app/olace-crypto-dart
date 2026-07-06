import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'offload/offload.dart';

const int _p2pJsonOffloadChars = 96 * 1024;
const int _p2pJsonEstimateCapChars = 256 * 1024;

Uint8List _encodeP2PCleartextWorker(Map<String, dynamic> payload) =>
    Uint8List.fromList(utf8.encode(jsonEncode(payload)));

String _jsonEncodeP2PEnvelopeWorker(Map<String, dynamic> envelope) =>
    jsonEncode(envelope);

Future<Map<String, dynamic>> _encryptP2PEnvelopeWorker(
  Map<String, dynamic> args,
) async {
  final payload = args['payload'] as Map<String, dynamic>;
  final sessionId = args['sessionId'] as String;
  final seq = args['seq'] as int;
  final localKeyVersion = args['localKeyVersion'] as int;
  final keyBytes = args['keyBytes'] as Uint8List;
  final nonce = _randomBytesWorker(12);
  final aad = utf8.encode('$sessionId|$seq|$localKeyVersion');
  final cleartext = Uint8List.fromList(utf8.encode(jsonEncode(payload)));
  final box = await AesGcm.with256bits().encrypt(
    cleartext,
    secretKey: SecretKey(keyBytes),
    nonce: nonce,
    aad: aad,
  );
  return {
    'type': 'enc',
    'v': 1,
    'session_id': sessionId,
    'seq': seq,
    'sender_key_version': localKeyVersion,
    'nonce': base64Encode(nonce),
    'ciphertext': base64Encode(box.cipherText),
    'tag': base64Encode(box.mac.bytes),
  };
}

Uint8List _randomBytesWorker(int length) {
  final random = Random.secure();
  final out = Uint8List(length);
  for (var i = 0; i < length; i += 1) {
    out[i] = random.nextInt(256);
  }
  return out;
}

int _roughP2PJsonStringChars(Object? value) {
  var total = 0;

  void walk(Object? node) {
    if (total >= _p2pJsonEstimateCapChars || node == null) return;
    if (node is String) {
      total += node.length;
      return;
    }
    if (node is List) {
      for (final item in node) {
        walk(item);
        if (total >= _p2pJsonEstimateCapChars) return;
      }
      return;
    }
    if (node is Map) {
      for (final entry in node.entries) {
        walk(entry.key);
        walk(entry.value);
        if (total >= _p2pJsonEstimateCapChars) return;
      }
    }
  }

  walk(value);
  return total;
}

Future<Uint8List> _encodeP2PCleartext(Map<String, dynamic> payload) {
  final roughChars = _roughP2PJsonStringChars(payload);
  if (roughChars >= _p2pJsonOffloadChars) {
    return offloadCompute(_encodeP2PCleartextWorker, payload);
  }
  return Future<Uint8List>.value(_encodeP2PCleartextWorker(payload));
}

Future<String> _encodeP2PEnvelopeJson(Map<String, dynamic> envelope) {
  final roughChars = _roughP2PJsonStringChars(envelope);
  if (roughChars >= _p2pJsonOffloadChars) {
    return offloadCompute(_jsonEncodeP2PEnvelopeWorker, envelope);
  }
  return Future<String>.value(jsonEncode(envelope));
}

/// A remote device's public identity: its static X25519 public key with
/// the SHA-256 fingerprint and key version registered for the account.
class P2PPeerIdentity {
  /// Creates a peer identity from its registered public fields.
  const P2PPeerIdentity({
    required this.deviceId,
    required this.publicKey,
    required this.fingerprint,
    required this.keyVersion,
  });

  /// Canonical device id (`didv1_...`).
  final String deviceId;

  /// Static X25519 public key, base64.
  final String publicKey;

  /// SHA-256 of the raw public key bytes, lowercase hex.
  final String fingerprint;

  /// Server-assigned key version, bumped on identity rotation.
  final int keyVersion;

  /// The public key as a `cryptography` X25519 [SimplePublicKey].
  SimplePublicKey toSimplePublicKey() {
    return SimplePublicKey(base64Decode(publicKey), type: KeyPairType.x25519);
  }
}

/// This device's identity: the peer fields plus the static X25519
/// private key. The private key never leaves the device.
class P2PLocalIdentity extends P2PPeerIdentity {
  /// Creates a local identity including the private key.
  P2PLocalIdentity({
    required super.deviceId,
    required super.publicKey,
    required super.fingerprint,
    required super.keyVersion,
    required this.privateKey,
    required this.createdAt,
  });

  /// Static X25519 private key, base64. Never leaves the device.
  final String privateKey;

  /// Creation time, epoch milliseconds.
  final int createdAt;

  /// The full keypair as a `cryptography` X25519 [SimpleKeyPairData].
  SimpleKeyPairData toKeyPairData() {
    return SimpleKeyPairData(
      base64Decode(privateKey),
      publicKey: toSimplePublicKey(),
      type: KeyPairType.x25519,
    );
  }
}

/// One session's AES-256-GCM state. Both peers hold the same session
/// key and encrypt under it with independently random 96-bit nonces; the
/// AAD `sessionId|seq|senderKeyVersion` pins every frame to its position
/// and the receive counter rejects replays. Byte-compatible with the Go
/// daemon's CryptoContext (olace-e2ee-go), enforced by shared vectors.
class P2PCryptoContext {
  /// Creates a session context. `sessionKey` must be the 32-byte key
  /// both peers derived for `sessionId`.
  P2PCryptoContext({
    required this.sessionId,
    required this.sessionKey,
    required this.localKeyVersion,
  });

  /// The session id both peers agreed on during the handshake.
  final String sessionId;

  /// The shared 32-byte AES-256-GCM session key.
  final SecretKey sessionKey;

  /// This device's identity key version, stamped into sent frames' AAD.
  final int localKeyVersion;
  int _sendSeq = 0;
  int _recvSeq = -1;

  /// Encrypt [payload] into a wire envelope
  /// `{type, v, session_id, seq, sender_key_version, nonce, ciphertext, tag}`.
  /// Large payloads are encoded and sealed on a worker isolate.
  Future<Map<String, dynamic>> encrypt(Map<String, dynamic> payload) async {
    final seq = _sendSeq++;
    final roughChars = _roughP2PJsonStringChars(payload);
    if (roughChars >= _p2pJsonOffloadChars) {
      final keyBytes = Uint8List.fromList(await sessionKey.extractBytes());
      return offloadCompute(_encryptP2PEnvelopeWorker, {
        'payload': payload,
        'sessionId': sessionId,
        'seq': seq,
        'localKeyVersion': localKeyVersion,
        'keyBytes': keyBytes,
      });
    }
    final nonce = P2PCrypto.randomBytes(12);
    final aad = utf8.encode('$sessionId|$seq|$localKeyVersion');
    final cleartext = await _encodeP2PCleartext(payload);
    final algo = AesGcm.with256bits();
    final box = await algo.encrypt(
      cleartext,
      secretKey: sessionKey,
      nonce: nonce,
      aad: aad,
    );
    return {
      'type': 'enc',
      'v': 1,
      'session_id': sessionId,
      'seq': seq,
      'sender_key_version': localKeyVersion,
      'nonce': base64Encode(nonce),
      'ciphertext': base64Encode(box.cipherText),
      'tag': base64Encode(box.mac.bytes),
    };
  }

  /// [encrypt] then JSON-encode the envelope (offloaded when large).
  Future<String> encryptToJson(Map<String, dynamic> payload) async {
    final envelope = await encrypt(payload);
    return _encodeP2PEnvelopeJson(envelope);
  }

  /// Decrypt a wire envelope. Returns null on session mismatch, replayed
  /// or missing sequence, malformed fields, or GCM authentication failure;
  /// the caller drops the frame either way, so failures are not
  /// distinguished.
  Future<Map<String, dynamic>?> decrypt(Map<String, dynamic> envelope) async {
    final session = (envelope['session_id'] as String? ?? '').trim();
    if (session != sessionId) return null;
    final seq = (envelope['seq'] as num?)?.toInt();
    if (seq == null || seq <= _recvSeq) return null;
    final nonceB64 = envelope['nonce'] as String? ?? '';
    final cipherB64 = envelope['ciphertext'] as String? ?? '';
    final tagB64 = envelope['tag'] as String? ?? '';
    if (nonceB64.isEmpty || cipherB64.isEmpty || tagB64.isEmpty) return null;
    final aad = utf8.encode(
      '$sessionId|$seq|${envelope['sender_key_version'] ?? 0}',
    );
    final algo = AesGcm.with256bits();
    try {
      final cleartext = await algo.decrypt(
        SecretBox(
          base64Decode(cipherB64),
          nonce: base64Decode(nonceB64),
          mac: Mac(base64Decode(tagB64)),
        ),
        secretKey: sessionKey,
        aad: aad,
      );
      _recvSeq = seq;
      final decoded = jsonDecode(utf8.decode(cleartext));
      if (decoded is Map<String, dynamic>) {
        return decoded;
      }
    } catch (_) {}
    return null;
  }
}

/// The E2EE session core for paired devices: X25519 key agreement,
/// HKDF-SHA256 session keys, HMAC-SHA256 transcript signing, and the
/// canonical handshake transcript builders. Byte-compatible mirror of
/// the Go daemon side (olace-e2ee-go); the shared test vectors pin both.
class P2PCrypto {
  P2PCrypto._();

  static final X25519 _x25519 = X25519();
  static final Hmac _hmacSha256 = Hmac.sha256();
  static final Random _random = Random.secure();

  /// Canonical `hello` transcript for the LAN P2P handshake. Every field
  /// both sides must agree on is pipe-joined in fixed order; the HMAC over
  /// this string ([signHelloOrAck]) is what makes field substitution by a
  /// relay or network attacker detectable.
  static String buildHelloTranscript({
    required String ticket,
    required String pairId,
    required String userId,
    required String mobileDeviceId,
    required String desktopDeviceId,
    required int mobileKeyVersion,
    required int desktopKeyVersion,
    required String sessionId,
    required String clientEphemeralPublicKey,
    required String clientNonce,
  }) {
    return [
      'hello',
      ticket,
      pairId,
      userId,
      mobileDeviceId,
      desktopDeviceId,
      '$mobileKeyVersion',
      '$desktopKeyVersion',
      sessionId,
      clientEphemeralPublicKey,
      clientNonce,
    ].join('|');
  }

  /// Canonical `ack` transcript for the LAN P2P handshake.
  static String buildAckTranscript({
    required String ticket,
    required String pairId,
    required String userId,
    required String mobileDeviceId,
    required String desktopDeviceId,
    required int mobileKeyVersion,
    required int desktopKeyVersion,
    required String sessionId,
    required String clientEphemeralPublicKey,
    required String serverEphemeralPublicKey,
    required String clientNonce,
    required String serverNonce,
  }) {
    return [
      'ack',
      ticket,
      pairId,
      userId,
      mobileDeviceId,
      desktopDeviceId,
      '$mobileKeyVersion',
      '$desktopKeyVersion',
      sessionId,
      clientEphemeralPublicKey,
      serverEphemeralPublicKey,
      clientNonce,
      serverNonce,
    ].join('|');
  }

  /// HKDF info string for the LAN P2P session key: binds the derived key
  /// to the ticket, pair, user, both devices, both ephemerals and nonces.
  static String buildSessionInfo({
    required String ticket,
    required String pairId,
    required String userId,
    required String mobileDeviceId,
    required String desktopDeviceId,
    required int mobileKeyVersion,
    required int desktopKeyVersion,
    required String sessionId,
    required String clientEphemeralPublicKey,
    required String serverEphemeralPublicKey,
    required String clientNonce,
    required String serverNonce,
  }) {
    return [
      'session',
      ticket,
      pairId,
      userId,
      mobileDeviceId,
      desktopDeviceId,
      '$mobileKeyVersion',
      '$desktopKeyVersion',
      sessionId,
      clientEphemeralPublicKey,
      serverEphemeralPublicKey,
      clientNonce,
      serverNonce,
    ].join('|');
  }

  /// Derive the LAN P2P session key: X25519 over BOTH the static
  /// identity keys and the fresh ephemeral keys, concatenated
  /// (static || ephemeral) into HKDF-SHA256 with salt
  /// `olace-p2p-session-v1`. The static half authenticates the devices;
  /// the ephemeral half freshens each session.
  static Future<P2PCryptoContext> deriveSessionContext({
    required String sessionId,
    required P2PLocalIdentity localIdentity,
    required P2PPeerIdentity peerIdentity,
    required SimpleKeyPairData localEphemeralKeyPair,
    required SimplePublicKey remoteEphemeralPublicKey,
    required String info,
  }) async {
    final staticShared = await _x25519.sharedSecretKey(
      keyPair: localIdentity.toKeyPairData(),
      remotePublicKey: peerIdentity.toSimplePublicKey(),
    );
    final ephemeralShared = await _x25519.sharedSecretKey(
      keyPair: localEphemeralKeyPair,
      remotePublicKey: remoteEphemeralPublicKey,
    );
    final merged = Uint8List.fromList([
      ...(await staticShared.extractBytes()),
      ...(await ephemeralShared.extractBytes()),
    ]);
    final hkdf = Hkdf(hmac: _hmacSha256, outputLength: 32);
    final sessionKey = await hkdf.deriveKey(
      secretKey: SecretKey(merged),
      nonce: utf8.encode('olace-p2p-session-v1'),
      info: utf8.encode(info),
    );
    return P2PCryptoContext(
      sessionId: sessionId,
      sessionKey: sessionKey,
      localKeyVersion: localIdentity.keyVersion,
    );
  }

  /// HKDF info string for the legacy (v1, static-key) relay session.
  static String buildSecureRelaySessionInfo({
    required String pairId,
    required String userId,
    required String mobileDeviceId,
    required String desktopDeviceId,
    required int mobileKeyVersion,
    required int desktopKeyVersion,
    required String sessionId,
  }) {
    return [
      'paired_e2ee_relay_v1',
      pairId,
      userId,
      mobileDeviceId,
      desktopDeviceId,
      '$mobileKeyVersion',
      '$desktopKeyVersion',
      sessionId,
    ].join('|');
  }

  /// Canonical `hello` transcript for the forward-secret relay handshake.
  static String buildSecureRelayHelloTranscript({
    required String pairId,
    required String userId,
    required String mobileDeviceId,
    required String desktopDeviceId,
    required int mobileKeyVersion,
    required int desktopKeyVersion,
    required String sessionId,
    required String desktopEphemeralPublicKey,
    required String desktopNonce,
  }) {
    return [
      'paired_e2ee_relay_hello_v2',
      pairId,
      userId,
      mobileDeviceId,
      desktopDeviceId,
      '$mobileKeyVersion',
      '$desktopKeyVersion',
      sessionId,
      desktopEphemeralPublicKey,
      desktopNonce,
    ].join('|');
  }

  /// Canonical `ack` transcript for the forward-secret relay handshake.
  static String buildSecureRelayAckTranscript({
    required String pairId,
    required String userId,
    required String mobileDeviceId,
    required String desktopDeviceId,
    required int mobileKeyVersion,
    required int desktopKeyVersion,
    required String sessionId,
    required String desktopEphemeralPublicKey,
    required String mobileEphemeralPublicKey,
    required String desktopNonce,
    required String mobileNonce,
  }) {
    return [
      'paired_e2ee_relay_ack_v2',
      pairId,
      userId,
      mobileDeviceId,
      desktopDeviceId,
      '$mobileKeyVersion',
      '$desktopKeyVersion',
      sessionId,
      desktopEphemeralPublicKey,
      mobileEphemeralPublicKey,
      desktopNonce,
      mobileNonce,
    ].join('|');
  }

  /// HKDF info string for the forward-secret relay session key.
  static String buildSecureRelayForwardSecretSessionInfo({
    required String pairId,
    required String userId,
    required String mobileDeviceId,
    required String desktopDeviceId,
    required int mobileKeyVersion,
    required int desktopKeyVersion,
    required String sessionId,
    required String desktopEphemeralPublicKey,
    required String mobileEphemeralPublicKey,
    required String desktopNonce,
    required String mobileNonce,
  }) {
    return [
      'paired_e2ee_relay_fs_v2',
      pairId,
      userId,
      mobileDeviceId,
      desktopDeviceId,
      '$mobileKeyVersion',
      '$desktopKeyVersion',
      sessionId,
      desktopEphemeralPublicKey,
      mobileEphemeralPublicKey,
      desktopNonce,
      mobileNonce,
    ].join('|');
  }

  /// Derive the legacy (v1) relay session key from the static identity
  /// keys only, HKDF-SHA256 salt `olace-paired-e2ee-v1`. Superseded by
  /// [deriveForwardSecretSessionContext] for new sessions; kept for
  /// wire compatibility.
  static Future<P2PCryptoContext> deriveStaticSessionContext({
    required String sessionId,
    required P2PLocalIdentity localIdentity,
    required P2PPeerIdentity peerIdentity,
    required String info,
  }) async {
    final staticShared = await _x25519.sharedSecretKey(
      keyPair: localIdentity.toKeyPairData(),
      remotePublicKey: peerIdentity.toSimplePublicKey(),
    );
    final hkdf = Hkdf(hmac: _hmacSha256, outputLength: 32);
    final sessionKey = await hkdf.deriveKey(
      secretKey: staticShared,
      nonce: utf8.encode('olace-paired-e2ee-v1'),
      info: utf8.encode(info),
    );
    return P2PCryptoContext(
      sessionId: sessionId,
      sessionKey: sessionKey,
      localKeyVersion: localIdentity.keyVersion,
    );
  }

  /// Derive the forward-secret relay session key: X25519 over ephemeral
  /// keys ONLY, HKDF-SHA256 salt `olace-paired-e2ee-relay-fs-v2`. A later
  /// compromise of a device's static identity key does not decrypt
  /// recorded relay traffic. Authentication comes separately from the
  /// transcript HMAC keyed by the static-static secret.
  static Future<P2PCryptoContext> deriveForwardSecretSessionContext({
    required String sessionId,
    required int localKeyVersion,
    required SimpleKeyPairData localEphemeralKeyPair,
    required SimplePublicKey remoteEphemeralPublicKey,
    required String info,
  }) async {
    final ephemeralShared = await _x25519.sharedSecretKey(
      keyPair: localEphemeralKeyPair,
      remotePublicKey: remoteEphemeralPublicKey,
    );
    final hkdf = Hkdf(hmac: _hmacSha256, outputLength: 32);
    final sessionKey = await hkdf.deriveKey(
      secretKey: ephemeralShared,
      nonce: utf8.encode('olace-paired-e2ee-relay-fs-v2'),
      info: utf8.encode(info),
    );
    return P2PCryptoContext(
      sessionId: sessionId,
      sessionKey: sessionKey,
      localKeyVersion: localKeyVersion,
    );
  }

  /// HMAC-SHA256 a handshake transcript with the auth key derived from
  /// the static-static X25519 secret (HKDF salt `olace-p2p-auth-v1`, info
  /// = the two device ids byte-sorted and pipe-joined). Returns base64.
  static Future<String> signHelloOrAck({
    required P2PLocalIdentity localIdentity,
    required P2PPeerIdentity peerIdentity,
    required String transcript,
  }) async {
    final staticShared = await _x25519.sharedSecretKey(
      keyPair: localIdentity.toKeyPairData(),
      remotePublicKey: peerIdentity.toSimplePublicKey(),
    );
    final hkdf = Hkdf(hmac: _hmacSha256, outputLength: 32);
    final orderedDeviceIds = [localIdentity.deviceId, peerIdentity.deviceId]
      ..sort();
    final authKey = await hkdf.deriveKey(
      secretKey: staticShared,
      nonce: utf8.encode('olace-p2p-auth-v1'),
      info: utf8.encode(orderedDeviceIds.join('|')),
    );
    final mac = await _hmacSha256.calculateMac(
      utf8.encode(transcript),
      secretKey: authKey,
    );
    return base64Encode(mac.bytes);
  }

  /// Verify a transcript signature from [signHelloOrAck] in constant
  /// time.
  static Future<bool> verifyHelloOrAck({
    required P2PLocalIdentity localIdentity,
    required P2PPeerIdentity peerIdentity,
    required String transcript,
    required String signature,
  }) async {
    final expected = await signHelloOrAck(
      localIdentity: localIdentity,
      peerIdentity: peerIdentity,
      transcript: transcript,
    );
    return _timingSafeEquals(base64Decode(expected), base64Decode(signature));
  }

  /// Generate a fresh X25519 keypair for a single handshake.
  static Future<SimpleKeyPairData> newEphemeralKeyPair() async {
    final pair = await _x25519.newKeyPair();
    final privateBytes = await pair.extractPrivateKeyBytes();
    final publicKey = await pair.extractPublicKey();
    return SimpleKeyPairData(
      privateBytes,
      publicKey: publicKey,
      type: KeyPairType.x25519,
    );
  }

  /// SHA-256 of the raw public key bytes, lowercase hex. The stable
  /// identity fingerprint shown to users and registered server-side.
  static Future<String> fingerprintForPublicKey(String publicKey) async {
    final sha = Sha256();
    final digest = await sha.hash(base64Decode(publicKey));
    return digest.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  static bool _timingSafeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var out = 0;
    for (var i = 0; i < a.length; i += 1) {
      out |= a[i] ^ b[i];
    }
    return out == 0;
  }

  /// Cryptographically secure random bytes (`Random.secure()`).
  static Uint8List randomBytes(int length) {
    final out = Uint8List(length);
    for (var i = 0; i < length; i += 1) {
      out[i] = _random.nextInt(256);
    }
    return out;
  }
}
