import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart' show Deflate, Inflate;
import 'package:olace_crypto/olace_crypto.dart';
import 'package:olace_crypto/src/compress/deflate_io.dart' as io;
import 'package:test/test.dart';

void main() {
  final mk = Uint8List.fromList(List<int>.generate(32, (i) => i * 7 % 256));
  const userId = 'user-1';
  const conversationId = 'conv-1';

  Map<String, dynamic> conversation(int messages) => {
        'id': conversationId,
        'title': 'A long chat',
        'messages': [
          for (var i = 0; i < messages; i++)
            {
              'id': 'm$i',
              'role': i.isEven ? 'user' : 'assistant',
              'content': 'Message $i talks about sync, zero knowledge and '
                  'why compression must come before encryption. ' * 3,
            },
        ],
      };

  for (final messages in [2, 400]) {
    // 2 runs inline; 400 is well past the 64 KiB worker threshold.
    test('zk2 round-trips and is smaller than zk1 ($messages messages)',
        () async {
      final payload = conversation(messages);
      final zk1 = await ZkCrypto.encryptConversationSized(mk, payload,
          userId: userId, conversationId: conversationId);
      final zk2 = await ZkCrypto.encryptConversationSized(mk, payload,
          userId: userId, conversationId: conversationId, compress: true);
      expect(zk1.token, startsWith('zk1:'));
      expect(zk2.token, startsWith('zk2:'));
      final plainLength = utf8.encode(jsonEncode(payload)).length;
      expect(zk1.plaintextBytes, plainLength);
      expect(zk2.plaintextBytes, plainLength);
      if (messages > 2) {
        expect(zk2.token.length, lessThan(zk1.token.length ~/ 3));
      }
      for (final token in [zk1.token, zk2.token]) {
        expect(
          await ZkCrypto.decryptConversation(mk, token,
              userId: userId, conversationId: conversationId),
          payload,
        );
      }
    });
  }

  test('the default stays zk1, so older clients can still read writes',
      () async {
    final token = await ZkCrypto.encryptConversation(mk, conversation(3),
        userId: userId, conversationId: conversationId);
    expect(token, startsWith('zk1:'));
  });

  test('a swapped prefix fails authentication in both directions', () async {
    final payload = conversation(3);
    final zk1 = await ZkCrypto.encryptConversation(mk, payload,
        userId: userId, conversationId: conversationId);
    final zk2 = await ZkCrypto.encryptConversation(mk, payload,
        userId: userId, conversationId: conversationId, compress: true);
    for (final forged in ['zk2:${zk1.substring(4)}', 'zk1:${zk2.substring(4)}']) {
      await expectLater(
        ZkCrypto.decryptConversation(mk, forged,
            userId: userId, conversationId: conversationId),
        throwsA(anything),
      );
    }
  });

  test('zk2 is bound to its purpose like zk1', () async {
    final zk2 = await ZkCrypto.encryptConversation(mk, conversation(3),
        userId: userId, conversationId: conversationId, compress: true);
    await expectLater(
      ZkCrypto.decryptConversation(mk, zk2,
          userId: userId, conversationId: 'another-conversation'),
      throwsA(anything),
    );
  });

  test('projects and research context read both envelopes', () async {
    final payload = {'name': 'p', 'files': List.filled(50, 'notes ' * 20)};
    final project = await ZkCrypto.encryptProject(mk, payload,
        userId: userId, projectId: 'p1', compress: true);
    expect(
        await ZkCrypto.decryptProject(mk, project,
            userId: userId, projectId: 'p1'),
        payload);
    final rctx = await ZkCrypto.encryptResearchContext(mk, payload,
        userId: userId, conversationId: conversationId, compress: true);
    expect(
        await ZkCrypto.decryptResearchContext(mk, rctx,
            userId: userId, conversationId: conversationId),
        payload);
  });

  test('native and web raw DEFLATE codecs interoperate', () {
    final data = utf8.encode('interop check ' * 500);
    expect(Inflate(io.deflateRaw(data)).getBytes(), data);
    expect(io.inflateRaw(Deflate(data, level: 6).getBytes()), data);
  });
}
