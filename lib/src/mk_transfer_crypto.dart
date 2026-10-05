import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'p2p_crypto.dart';

/// Cryptographically-bound short authentication string for an MK transfer.
/// Both devices derive an identical instance from the HKDF transcript over
/// (responder_pub || requester_pub || transfer_id). The new device shows
/// [realSas]; the user taps it among [options] on the device holding the
/// MK, which checks the tap itself before it encrypts anything.
class SasChallenge {
  /// Creates a challenge; see [MkTransferCrypto.computeSasOptions].
  const SasChallenge({
    required this.realSas,
    required this.options,
    this.transferId = '',
  });

  /// The matching 3-digit value, zero-padded ("000".."999"). Both devices
  /// compute the same value; the new device shows it and the MK holder
  /// requires the user's tap to equal it.
  final String realSas;

  /// 5 zero-padded 3-digit options in deterministic order (same on both
  /// devices). Contains [realSas] plus 4 transcript-derived decoys.
  final List<String> options;

  /// transfer_id this challenge belongs to. Populated by the service
  /// before passing into the requester-side builder so the UI can
  /// disambiguate concurrent transfers.
  final String transferId;
}

/// The requester's commitment to its ephemeral public key, sent before the
/// responder reveals its own key. See [MkTransferCrypto.commitRequesterKey].
class MkTransferCommitment {
  /// Creates a commitment; see [MkTransferCrypto.commitRequesterKey].
  const MkTransferCommitment({required this.commit, required this.nonce});

  /// base64url SHA-256 digest; crosses in the transfer request.
  final String commit;

  /// base64url 32-byte random nonce; stays on the requester until it
  /// reveals its public key.
  final String nonce;
}

/// Crypto for transferring the Master Key between two signed-in devices:
/// ephemeral X25519 + HKDF transfer key, a commit-then-reveal of the
/// requester's key, SAS number-match verification, and an AES-256-GCM
/// envelope with the confirmed SAS folded into the AAD.
///
/// Message order (every message passes through the server):
///   1. requester -> responder: [commitRequesterKey] digest only
///   2. responder -> requester: responder public key
///   3. requester -> responder: requester public key + nonce, sent only
///      after step 2 arrived; the requester never accepts a second
///      responder key after it revealed
///   4. responder: [verifyRequesterCommit], then the SAS
///
/// Without step 1, a server relaying the keys could pick its substitute key
/// toward the requester after seeing both real keys and grind it until the
/// two 3-digit SAS values agree (about a thousand tries). With it, both
/// substitutes are fixed before either real key is known, so the server
/// gets one blind guess at a 1-in-1000 match and a miss is visible.
class MkTransferCrypto {
  MkTransferCrypto._();

  static final X25519 _x25519 = X25519();
  static final AesGcm _aesGcm = AesGcm.with256bits();
  static final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  static final Sha256 _sha256 = Sha256();

  /// Length of the random nonce bound into a requester commitment.
  static const int commitNonceLength = 32;

  static const String _commitLabel = 'olace-mk-commit-v1';

  /// Commit to [requesterEphemeralPub] for [transferId]:
  /// `SHA-256("olace-mk-commit-v1" || 0x00 || transferId || 0x00 ||
  /// pub || nonce)`, with a fresh 32-byte nonce.
  static Future<MkTransferCommitment> commitRequesterKey({
    required SimplePublicKey requesterEphemeralPub,
    required String transferId,
  }) async {
    final nonce = P2PCrypto.randomBytes(commitNonceLength);
    final digest = await commitDigest(
      requesterPublicKey: requesterEphemeralPub.bytes,
      nonce: nonce,
      transferId: transferId,
    );
    return MkTransferCommitment(
      commit: base64Url.encode(digest),
      nonce: base64Url.encode(nonce),
    );
  }

  /// The commitment digest over raw inputs; exposed for test vectors.
  static Future<Uint8List> commitDigest({
    required List<int> requesterPublicKey,
    required List<int> nonce,
    required String transferId,
  }) async {
    if (requesterPublicKey.length != 32) {
      throw const FormatException('Requester public key must be 32 bytes');
    }
    if (nonce.length != commitNonceLength) {
      throw const FormatException('Commit nonce must be 32 bytes');
    }
    final hash = await _sha256.hash([
      ...utf8.encode(_commitLabel),
      0,
      ...utf8.encode(transferId),
      0,
      ...requesterPublicKey,
      ...nonce,
    ]);
    return Uint8List.fromList(hash.bytes);
  }

  /// True when [requesterEphemeralPubB64] and [nonceB64] open [commit] for
  /// [transferId]. Malformed input is false, never an exception.
  static Future<bool> verifyRequesterCommit({
    required String commit,
    required String requesterEphemeralPubB64,
    required String nonceB64,
    required String transferId,
  }) async {
    try {
      final expected = _decodeB64(commit);
      final digest = await commitDigest(
        requesterPublicKey: _decodeB64(requesterEphemeralPubB64),
        nonce: _decodeB64(nonceB64),
        transferId: transferId,
      );
      if (expected.length != digest.length) return false;
      var diff = 0;
      for (var i = 0; i < digest.length; i++) {
        diff |= expected[i] ^ digest[i];
      }
      return diff == 0;
    } catch (_) {
      return false;
    }
  }

  static Uint8List _decodeB64(String value) {
    final trimmed = value.trim();
    try {
      return base64Url.decode(base64Url.normalize(trimmed));
    } on FormatException {
      return base64.decode(base64.normalize(trimmed));
    }
  }

  /// Derive the 5-option SAS challenge for a transfer.
  ///
  /// Both devices independently derive the same challenge from the ECDH
  /// transcript. A machine in the middle substituting either side's
  /// ephemeral pubkey produces a different [SasChallenge.realSas] on each
  /// side, provided the requester committed to its key first (see the
  /// class comment): the new device then shows a number the MK holder does
  /// not accept. The SAS is also folded into the MK-encryption AAD.
  ///
  /// Returns a [SasChallenge] with `transferId` populated so downstream
  /// UI / state notifiers can disambiguate concurrent transfers without
  /// tracking it out-of-band.
  static Future<SasChallenge> computeSasOptions({
    required SimplePublicKey responderEphemeralPub,
    required SimplePublicKey requesterEphemeralPub,
    required String transferId,
  }) async {
    // Canonical IKM ordering: byte-sort the two pubkeys before concat
    // so the IKM is independent of which pubkey was passed under which
    // role-named kwarg. A future caller that swaps the kwargs (easy
    // mistake — name-based ordering hides positional intent) would
    // otherwise silently compute a different SAS on one device. With
    // byte-sort, both devices produce identical IKM regardless of
    // caller order. MITM detection still works: a swapped pubkey
    // produces a different byte sequence regardless of sort position.
    final aBytes = responderEphemeralPub.bytes;
    final bBytes = requesterEphemeralPub.bytes;
    final ordered =
        _byteCompare(aBytes, bBytes) <= 0 ? [aBytes, bBytes] : [bBytes, aBytes];
    final ikm = Uint8List.fromList([...ordered[0], ...ordered[1]]);
    final outKey = await _hkdf.deriveKey(
      secretKey: SecretKey(ikm),
      nonce: utf8.encode('olace-mk-sas-v1'),
      info: utf8.encode('sas|$transferId'),
    );
    final out = await outKey.extractBytes();
    final realInt = ((out[0] << 8) | out[1]) % 1000;
    final realSas = realInt.toString().padLeft(3, '0');
    // Deterministic byte-cursor PRNG over the remaining HKDF output —
    // both sides walk the same bytes in the same order, so option sets
    // match exactly.
    var cursor = 2;
    int nextByte() {
      final b = out[cursor % out.length];
      cursor += 1;
      return b;
    }

    final picked = <int>{realInt};
    var safety = 0;
    while (picked.length < 5 && safety < 64) {
      final candidate = ((nextByte() << 8) | nextByte()) % 1000;
      picked.add(candidate);
      safety++;
    }
    // Fallback if the HKDF byte stream produced too many `% 1000` collisions
    // in 64 attempts (essentially impossible for a uniform stream). Linear
    // probe from realInt+1; guaranteed to terminate quickly because there
    // are 1000 distinct candidate values and we need at most 5.
    var probe = (realInt + 1) % 1000;
    while (picked.length < 5) {
      picked.add(probe);
      probe = (probe + 1) % 1000;
    }
    final list = picked.toList();
    // Fisher-Yates with deterministic byte stream.
    for (var i = list.length - 1; i > 0; i--) {
      final j = nextByte() % (i + 1);
      final tmp = list[i];
      list[i] = list[j];
      list[j] = tmp;
    }
    final options = list.map((n) => n.toString().padLeft(3, '0')).toList();
    return SasChallenge(
      realSas: realSas,
      options: options,
      transferId: transferId,
    );
  }

  /// Lexicographic byte comparison. Returns negative if [a]<[b], 0 if equal,
  /// positive if [a]>[b]. Used by [computeSasOptions] to canonicalize IKM.
  static int _byteCompare(List<int> a, List<int> b) {
    final n = a.length < b.length ? a.length : b.length;
    for (var i = 0; i < n; i++) {
      final d = a[i] - b[i];
      if (d != 0) return d;
    }
    return a.length - b.length;
  }

  /// Encrypt an MK payload for transfer.
  ///
  /// [sas] is required — AAD is always `mk-transfer-v2|$transferId|sas=$sas`.
  /// The old device calls this only after it verified the requester's
  /// commitment and the user's tap equalled its own [SasChallenge.realSas],
  /// checked on this device. A server that swapped ephemerals cannot make
  /// the new device show that number except by a 1-in-1000 blind guess, so
  /// the old device never reaches this call and no envelope exists to
  /// steal. The AAD binding is defense-in-depth.
  static Future<String> encryptMk({
    required SimpleKeyPair localKeyPair,
    required SimplePublicKey remotePublicKey,
    required String transferId,
    required Uint8List mk,
    required String sas,
  }) async {
    final key = await _deriveTransferKey(
      localKeyPair,
      remotePublicKey,
      transferId,
    );
    final nonce = P2PCrypto.randomBytes(12);
    final aadStr = 'mk-transfer-v2|$transferId|sas=$sas';
    final box = await _aesGcm.encrypt(
      mk,
      secretKey: key,
      nonce: nonce,
      aad: utf8.encode(aadStr),
    );
    final combined = Uint8List.fromList([
      ...nonce,
      ...box.cipherText,
      ...box.mac.bytes,
    ]);
    return base64Url.encode(combined);
  }

  /// Decrypt an encrypted MK payload.
  ///
  /// [sas] is required — the AAD is always `mk-transfer-v2|$transferId|sas=$sas`.
  /// Callers that have no confirmed SAS must NOT call this (the bundled MK
  /// cannot be decrypted without it); skip the transfer instead.
  static Future<Uint8List> decryptMk({
    required SimpleKeyPair localKeyPair,
    required SimplePublicKey remotePublicKey,
    required String transferId,
    required String encryptedMkB64,
    required String sas,
  }) async {
    final key = await _deriveTransferKey(
      localKeyPair,
      remotePublicKey,
      transferId,
    );
    final combined = base64Url.decode(encryptedMkB64);
    if (combined.length < 28) {
      throw const FormatException('Invalid encrypted MK length');
    }
    final nonce = combined.sublist(0, 12);
    final cipherText = combined.sublist(12, combined.length - 16);
    final tag = combined.sublist(combined.length - 16);
    final aadStr = 'mk-transfer-v2|$transferId|sas=$sas';
    final cleartext = await _aesGcm.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
      secretKey: key,
      aad: utf8.encode(aadStr),
    );
    return Uint8List.fromList(cleartext);
  }

  static Future<SecretKey> _deriveTransferKey(
    SimpleKeyPair localKeyPair,
    SimplePublicKey remotePublicKey,
    String transferId,
  ) async {
    final shared = await _x25519.sharedSecretKey(
      keyPair: localKeyPair,
      remotePublicKey: remotePublicKey,
    );
    return _hkdf.deriveKey(
      secretKey: shared,
      nonce: utf8.encode('olace-mk-transfer-v1'),
      info: utf8.encode('mk-transfer|$transferId'),
    );
  }
}
