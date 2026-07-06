import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'p2p_crypto.dart';

/// Result of PIN vault key derivation ([PinVault.deriveVaultKey]).
class PinVaultKeys {
  /// The peppered vault key: encrypts the recovery key, produces the auth tag.
  final SecretKey vaultKey;

  /// HMAC over a fixed constant under the vault key. Proves knowledge of
  /// the correctly derived vault key without revealing it.
  final Uint8List authTag;

  /// [authTag] as lowercase hex. The server stores only the SHA-256 of
  /// this tag (see [PinVault.hashAuthTag]), never the tag itself.
  final String authTagHex;

  /// Bundles the outputs of [PinVault.deriveVaultKey].
  PinVaultKeys({
    required this.vaultKey,
    required this.authTag,
    required this.authTagHex,
  });
}

/// The PIN vault's three-stage key derivation and recovery-key envelope.
///
/// The PIN never leaves the device and the server never sees it: stage 2
/// sends only a one-way blinded value to the server, which applies its
/// KMS-held pepper and returns the hardened result. A database-only leak
/// has no pepper, so it cannot brute-force vaults offline.
class PinVault {
  PinVault._();

  static final AesGcm _aesGcm = AesGcm.with256bits();
  static final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  /// Stage 1 of PIN-vault key derivation: the raw PIN key.
  ///
  /// Argon2id (memory-hard) because the PIN is low-entropy (~20 bits). The
  /// PIN key is NOT used directly — it must be blinded ([computeHardenBlind]),
  /// hardened server-side with the pepper, then run through [deriveVaultKey].
  /// Callers MUST pass the vault's stored params (read back from the server at
  /// unlock, or the setup service's constants at creation) — the defaults here
  /// only document the current new-vault standard and must never be used to
  /// reproduce an existing vault, which may carry different params.
  static Future<SecretKey> derivePinKey(
    String pin,
    Uint8List salt, {
    int argon2T = 2,
    int argon2M = 32768,
    int argon2P = 4,
  }) async {
    final argon2id = Argon2id(
      parallelism: argon2P,
      memory: argon2M, // KiB
      iterations: argon2T,
      hashLength: 32,
    );
    return argon2id.deriveKey(
      secretKey: SecretKey(utf8.encode(pin)),
      nonce: salt,
    );
  }

  /// Stage 2: blind the PIN key for the server-side pepper round-trip.
  ///
  /// The result is sent to `POST /sync/encryption/pin-vault/harden`; the
  /// server applies its KMS-held pepper (`hardened = HMAC(pepper, blind ||
  /// userId)`) and returns `hardened`. The server never sees the PIN — only
  /// this one-way blinded value.
  static Future<Uint8List> computeHardenBlind(SecretKey pinKey) async {
    final mac = await Hmac.sha256().calculateMac(
      utf8.encode('olace-pv-harden-blind-v1'),
      secretKey: pinKey,
    );
    return Uint8List.fromList(mac.bytes);
  }

  /// Stage 3: derive the PIN-vault key + auth tag from the PIN key and the
  /// server-hardened value. The vault key — not the bare PIN key — encrypts
  /// the recovery key and produces the auth tag, so a DB-only leak (which
  /// has no pepper) cannot reproduce it.
  static Future<PinVaultKeys> deriveVaultKey(
    SecretKey pinKey,
    Uint8List hardened,
  ) async {
    final vaultKey = await _hkdf.deriveKey(
      secretKey: pinKey,
      nonce: hardened,
      info: utf8.encode('olace-pin-vault-key-v2'),
    );
    final authMac = await Hmac.sha256().calculateMac(
      utf8.encode('olace-pin-vault-auth-v2'),
      secretKey: vaultKey,
    );
    final authTag = Uint8List.fromList(authMac.bytes);
    final authTagHex =
        authTag.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return PinVaultKeys(
      vaultKey: vaultKey,
      authTag: authTag,
      authTagHex: authTagHex,
    );
  }

  /// Encrypt recovery key bytes with the peppered vault key.
  ///
  /// Returns base64url-encoded `nonce(12) || ciphertext || tag(16)`.
  static Future<String> encryptRecoveryKeyForVault(
    SecretKey vaultKey,
    Uint8List recoveryKeyBytes,
    String userId,
  ) async {
    final nonce = P2PCrypto.randomBytes(12);
    final aad = utf8.encode('olace-pin-vault-v2|$userId');
    final box = await _aesGcm.encrypt(
      recoveryKeyBytes,
      secretKey: vaultKey,
      nonce: nonce,
      aad: aad,
    );
    final combined = Uint8List.fromList([
      ...nonce,
      ...box.cipherText,
      ...box.mac.bytes,
    ]);
    return base64Url.encode(combined);
  }

  /// Decrypt recovery key bytes from the vault using the peppered vault key.
  ///
  /// Throws on wrong PIN (GCM auth failure).
  static Future<Uint8List> decryptRecoveryKeyFromVault(
    SecretKey vaultKey,
    String encryptedRkB64,
    String userId,
  ) async {
    final combined = base64Url.decode(encryptedRkB64);
    if (combined.length < 28) {
      throw const FormatException('Invalid vault ciphertext length');
    }
    final nonce = combined.sublist(0, 12);
    final cipherText = combined.sublist(12, combined.length - 16);
    final tag = combined.sublist(combined.length - 16);
    final aad = utf8.encode('olace-pin-vault-v2|$userId');
    final cleartext = await _aesGcm.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
      secretKey: vaultKey,
      aad: aad,
    );
    return Uint8List.fromList(cleartext);
  }

  /// Compute SHA-256 hash of the auth tag, returned as hex string.
  ///
  /// The server stores this hash — not the raw auth tag.
  static Future<String> hashAuthTag(Uint8List authTag) async {
    final sha256 = Sha256();
    final digest = await sha256.hash(authTag);
    return digest.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
