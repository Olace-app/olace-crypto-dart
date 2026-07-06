import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'p2p_crypto.dart';

/// Cryptographically-bound short authentication string for the standalone
/// MK transfer flow. Both devices derive an identical instance from the
/// HKDF transcript over (responder_pub || requester_pub || transfer_id).
/// User matches the same 3-digit number on both screens to authorize.
class SasChallenge {
  /// Creates a challenge; see [MkTransferCrypto.computeSasOptions].
  const SasChallenge({
    required this.realSas,
    required this.options,
    this.transferId = '',
  });

  /// The matching 3-digit value, zero-padded ("000".."999"). Both devices
  /// compute the same value; user must tap this one.
  final String realSas;

  /// 5 zero-padded 3-digit options in deterministic order (same on both
  /// devices). Contains [realSas] plus 4 transcript-derived decoys.
  final List<String> options;

  /// transfer_id this challenge belongs to. Populated by the service
  /// before passing into the requester-side builder so the UI can
  /// disambiguate concurrent transfers.
  final String transferId;
}

/// Crypto for transferring the Master Key between two signed-in devices:
/// ephemeral X25519 + HKDF transfer key, SAS number-match verification,
/// and an AES-256-GCM envelope with the confirmed SAS folded into the AAD.
class MkTransferCrypto {
  MkTransferCrypto._();

  static final X25519 _x25519 = X25519();
  static final AesGcm _aesGcm = AesGcm.with256bits();
  static final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  /// Derive the 5-option SAS challenge for a transfer.
  ///
  /// Both devices independently derive the same challenge from the ECDH
  /// transcript. A machine in the middle substituting either side's
  /// ephemeral pubkey would produce different option sets on each side,
  /// and the user refuses on visual mismatch. As defense-in-depth the
  /// chosen SAS value is folded into the MK-encryption AAD, so even an
  /// accidental "lucky tap" collision can't unlock the MK.
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
  /// The old device only calls this AFTER the user has visually verified a
  /// transcript-derived SAS by tapping the matching number. If a malicious
  /// backend swapped ephemerals, the SAS values would differ between devices,
  /// the user wouldn't find a matching number to tap, and the old device
  /// would never reach this call → no encrypted MK on the wire → no leak.
  /// The AAD binding is defense-in-depth.
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
