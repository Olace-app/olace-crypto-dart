// Finding #14 stage 1: ZK crypto for payloads >= 64 KiB runs on a worker
// isolate (native) via offloadCompute. Output must stay byte-identical to the
// inline path, so these round-trip large payloads through the public API and
// confirm they decrypt back exactly. Small payloads exercise the inline path.

import 'dart:convert';
import 'dart:typed_data';

import 'package:olace_crypto/olace_crypto.dart';
import 'package:test/test.dart';

void main() {
  final mk = Uint8List.fromList(List.generate(32, (i) => (i * 7 + 3) & 0xff));
  const userId = 'user-offload';
  const conversationId = 'conv-offload';
  const attachmentId = 'att-offload';

  test('conversation envelope round-trips a >64KiB payload (offload path)',
      () async {
    // A payload whose JSON encoding comfortably exceeds the 64 KiB gate.
    final big = List.generate(4000, (i) => 'message body chunk number $i ' * 2);
    final payload = <String, dynamic>{'messages': big, 'n': big.length};
    expect(utf8.encode(jsonEncode(payload)).length, greaterThan(64 * 1024));

    final ct = await ZkCrypto.encryptConversation(
      mk,
      payload,
      userId: userId,
      conversationId: conversationId,
    );
    expect(ct, startsWith('zk1:'));
    final back = await ZkCrypto.decryptConversation(
      mk,
      ct,
      userId: userId,
      conversationId: conversationId,
    );
    expect(back['n'], big.length);
    expect((back['messages'] as List).length, big.length);
    expect(back['messages'], payload['messages']);

    // Purpose binding still holds through the offload path.
    await expectLater(
      ZkCrypto.decryptConversation(mk, ct,
          userId: userId, conversationId: 'conv-other'),
      throwsA(anything),
    );
  });

  test('media blob round-trips a >64KiB payload (offload path)', () async {
    final blob = Uint8List.fromList(
      List.generate(200 * 1024, (i) => (i * 31 + 5) & 0xff),
    );
    expect(blob.length, greaterThan(64 * 1024));

    final enc = await ZkCrypto.encryptMediaBlob(
      mk,
      blob,
      userId: userId,
      attachmentId: attachmentId,
    );
    final back = await ZkCrypto.decryptMediaBlob(
      mk,
      enc,
      userId: userId,
      attachmentId: attachmentId,
    );
    expect(back, blob);

    // Wrong attachment id must fail closed even on the offload path.
    await expectLater(
      ZkCrypto.decryptMediaBlob(mk, enc,
          userId: userId, attachmentId: 'att-other'),
      throwsA(anything),
    );
  });

  test('small conversation payload still round-trips (inline path)', () async {
    final payload = <String, dynamic>{'hello': 'world'};
    final ct = await ZkCrypto.encryptConversation(
      mk,
      payload,
      userId: userId,
      conversationId: conversationId,
    );
    final back = await ZkCrypto.decryptConversation(
      mk,
      ct,
      userId: userId,
      conversationId: conversationId,
    );
    expect(back, payload);
  });

  test('a large offloaded ciphertext decrypts under a fresh MK object',
      () async {
    // The worker receives MK bytes by value; a fresh Uint8List with the same
    // bytes must decrypt identically (no reliance on object identity).
    final payload = <String, dynamic>{
      'blob': 'x' * (80 * 1024),
    };
    final ct = await ZkCrypto.encryptConversation(
      mk,
      payload,
      userId: userId,
      conversationId: conversationId,
    );
    final mkCopy = Uint8List.fromList(mk);
    final back = await ZkCrypto.decryptConversation(
      mkCopy,
      ct,
      userId: userId,
      conversationId: conversationId,
    );
    expect(back['blob'], payload['blob']);
  });
}
