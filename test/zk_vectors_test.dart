// Zero-knowledge backup + PIN vault vector tests.
//
// test/vectors/zk_vectors.json pins the zk1 envelope format, MK wrap, the
// per-purpose HKDF derivations, the PIN-vault 3-stage derivation, and the
// Crockford recovery-key format. These bytes are what shipped Olace
// clients have already written to user backups: a failure here means
// existing backups stop decrypting. Fix the code, never the vectors.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:olace_crypto/olace_crypto.dart';
import 'package:test/test.dart';

Uint8List hexDecode(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String hexEncode(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final vectors = jsonDecode(
    File('test/vectors/zk_vectors.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final inputs = vectors['inputs'] as Map<String, dynamic>;
  final det = vectors['deterministic'] as Map<String, dynamic>;
  final dv = vectors['decrypt_vectors'] as Map<String, dynamic>;

  final mk = hexDecode(inputs['mk_hex'] as String);
  final rk = hexDecode(inputs['rk_hex'] as String);
  final userId = inputs['user_id'] as String;
  final conversationId = inputs['conversation_id'] as String;
  final projectId = inputs['project_id'] as String;
  final attachmentId = inputs['attachment_id'] as String;
  final pin = inputs['pin'] as String;
  final pinSalt = hexDecode(inputs['pin_salt_hex'] as String);
  final hardened = hexDecode(inputs['hardened_hex'] as String);
  final argon = inputs['argon2'] as Map<String, dynamic>;

  test('deterministic PIN vault derivations match', () async {
    final pinKey = await PinVault.derivePinKey(
      pin,
      pinSalt,
      argon2T: argon['t'] as int,
      argon2M: argon['m'] as int,
      argon2P: argon['p'] as int,
    );
    expect(hexEncode(await pinKey.extractBytes()), det['pin_key_hex']);
    final blind = await PinVault.computeHardenBlind(pinKey);
    expect(hexEncode(blind), det['harden_blind_hex']);
    final vault = await PinVault.deriveVaultKey(pinKey, hardened);
    expect(
        hexEncode(await vault.vaultKey.extractBytes()), det['vault_key_hex']);
    expect(vault.authTagHex, det['auth_tag_hex']);
    expect(
        await PinVault.hashAuthTag(vault.authTag), det['auth_tag_sha256_hex']);
  });

  test('recovery key format + Crockford normalization', () {
    final formatted = det['recovery_key_formatted'] as String;
    expect(RecoveryKey.format(rk), formatted);
    expect(RecoveryKey.parse(formatted), rk);
    final mangled = formatted
        .toLowerCase()
        .replaceAll('0', 'O')
        .replaceAll('1', 'i')
        .replaceAll('-', ' ');
    expect(RecoveryKey.parse(mangled), rk);
    expect(RecoveryKey.parse('!!!!'), isNull);
  });

  test('MK unwrap vector', () async {
    expect(await ZkCrypto.unwrapMk(dv['wrapped_mk_b64'] as String, rk, userId),
        mk);
    final wrongRk = Uint8List.fromList(List.filled(16, 0));
    await expectLater(
      ZkCrypto.unwrapMk(dv['wrapped_mk_b64'] as String, wrongRk, userId),
      throwsA(anything),
    );
  });

  test('zk1 payload decrypt vectors', () async {
    expect(
      await ZkCrypto.decryptConversation(mk, dv['conversation_zk1'] as String,
          userId: userId, conversationId: conversationId),
      isA<Map<String, dynamic>>(),
    );
    expect(
      await ZkCrypto.decryptProject(mk, dv['project_zk1'] as String,
          userId: userId, projectId: projectId),
      isA<Map<String, dynamic>>(),
    );
    expect(
      await ZkCrypto.decryptResearchContext(
          mk, dv['research_context_zk1'] as String,
          userId: userId, conversationId: conversationId),
      isA<Map<String, dynamic>>(),
    );
    expect(
      await ZkCrypto.decryptInstructions(mk, dv['instructions_zk1'] as String,
          userId: userId),
      isA<Map<String, dynamic>>(),
    );
    expect(
      await ZkCrypto.decryptByokVault(mk, dv['byok_vault_zk1'] as String,
          userId: userId),
      isA<Map<String, dynamic>>(),
    );
    // Purpose binding: a conversation ciphertext must not decrypt under a
    // different conversation id (HKDF purpose + AAD both differ).
    await expectLater(
      ZkCrypto.decryptConversation(mk, dv['conversation_zk1'] as String,
          userId: userId, conversationId: 'conv-other'),
      throwsA(anything),
    );
  });

  test('media blob + attachment metadata decrypt vectors', () async {
    final blob = await ZkCrypto.decryptMediaBlob(
      mk,
      Uint8List.fromList(base64Decode(dv['media_blob_b64'] as String)),
      userId: userId,
      attachmentId: attachmentId,
    );
    expect(blob, isNotEmpty);
    expect(
      await ZkCrypto.decryptAttachmentMetadata(
          mk, dv['attachment_meta_b64'] as String,
          userId: userId, attachmentId: attachmentId, field: 'file_name'),
      isNotEmpty,
    );
    // Field binding: file_name ciphertext must not decrypt as mime_type.
    await expectLater(
      ZkCrypto.decryptAttachmentMetadata(
          mk, dv['attachment_meta_b64'] as String,
          userId: userId, attachmentId: attachmentId, field: 'mime_type'),
      throwsA(anything),
    );
  });

  test('PIN vault recovery key decrypt vector', () async {
    final vaultKey = SecretKey(hexDecode(det['vault_key_hex'] as String));
    expect(
      await PinVault.decryptRecoveryKeyFromVault(
          vaultKey, dv['vault_encrypted_rk_b64'] as String, userId),
      rk,
    );
    final wrongKey = SecretKey(Uint8List.fromList(List.filled(32, 1)));
    await expectLater(
      PinVault.decryptRecoveryKeyFromVault(
          wrongKey, dv['vault_encrypted_rk_b64'] as String, userId),
      throwsA(anything),
    );
  });

  test('wrap/unwrap + generateKeys round trip', () async {
    final keys = ZkCrypto.generateKeys();
    expect(keys.mk, hasLength(32));
    expect(RecoveryKey.parse(keys.recoveryKey), keys.recoveryKeyBytes);
    final wrapped =
        await ZkCrypto.wrapMk(keys.mk, keys.recoveryKeyBytes, userId);
    expect(await ZkCrypto.unwrapMk(wrapped, keys.recoveryKeyBytes, userId),
        keys.mk);
  });

  test('MK transfer: SAS is order-independent, envelope is SAS-bound',
      () async {
    final x25519 = X25519();
    final a = await x25519.newKeyPair();
    final b = await x25519.newKeyPair();
    final aPub = await a.extractPublicKey();
    final bPub = await b.extractPublicKey();

    final c1 = await MkTransferCrypto.computeSasOptions(
      responderEphemeralPub: aPub,
      requesterEphemeralPub: bPub,
      transferId: 'transfer-0001',
    );
    final c2 = await MkTransferCrypto.computeSasOptions(
      responderEphemeralPub: bPub,
      requesterEphemeralPub: aPub,
      transferId: 'transfer-0001',
    );
    expect(c1.realSas, c2.realSas);
    expect(c1.options, c2.options);
    expect(c1.options, contains(c1.realSas));
    expect(c1.options.toSet(), hasLength(5));

    final encrypted = await MkTransferCrypto.encryptMk(
      localKeyPair: a,
      remotePublicKey: bPub,
      transferId: 'transfer-0001',
      mk: mk,
      sas: c1.realSas,
    );
    expect(
      await MkTransferCrypto.decryptMk(
        localKeyPair: b,
        remotePublicKey: aPub,
        transferId: 'transfer-0001',
        encryptedMkB64: encrypted,
        sas: c1.realSas,
      ),
      mk,
    );
    // Wrong SAS in the AAD must fail closed.
    await expectLater(
      MkTransferCrypto.decryptMk(
        localKeyPair: b,
        remotePublicKey: aPub,
        transferId: 'transfer-0001',
        encryptedMkB64: encrypted,
        sas: '000' == c1.realSas ? '001' : '000',
      ),
      throwsA(anything),
    );
  });
}
