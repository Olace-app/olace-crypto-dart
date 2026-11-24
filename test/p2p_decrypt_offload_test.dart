import 'package:cryptography/cryptography.dart';
import 'package:olace_crypto/olace_crypto.dart';
import 'package:test/test.dart';

P2PCryptoContext _context() => P2PCryptoContext(
  sessionId: 'session-1',
  sessionKey: SecretKey(List<int>.generate(32, (i) => i)),
  localKeyVersion: 1,
);

void main() {
  test('a large frame decrypts off the caller and keeps its place', () async {
    final sender = _context();
    final receiver = _context();
    final big = await sender.encrypt({'data': 'x' * (512 * 1024)});
    final small = await sender.encrypt({'data': 'tail'});

    final first = receiver.decrypt(big);
    final second = receiver.decrypt(small);

    expect((await first)?['data'], 'x' * (512 * 1024));
    expect((await second)?['data'], 'tail');
  });

  test('a replayed large frame is refused', () async {
    final sender = _context();
    final receiver = _context();
    final big = await sender.encrypt({'data': 'y' * (512 * 1024)});

    expect(await receiver.decrypt(big), isNotNull);
    expect(await receiver.decrypt(big), isNull);
  });

  test('a tampered large frame is refused', () async {
    final sender = _context();
    final receiver = _context();
    final big = await sender.encrypt({'data': 'z' * (512 * 1024)});
    final tag = big['tag'] as String;
    big['tag'] = '${tag[0] == 'A' ? 'B' : 'A'}${tag.substring(1)}';

    expect(await receiver.decrypt(big), isNull);
  });

  test('small, large, small back to back arrive in order', () async {
    final sender = _context();
    final receiver = _context();
    final frames = [
      await sender.encrypt({'n': 1}),
      await sender.encrypt({'n': 2, 'data': 'b' * (512 * 1024)}),
      await sender.encrypt({'n': 3}),
    ];
    final delivered = <int>[];
    await Future.wait([
      for (final f in frames)
        receiver.decrypt(f).then((m) => delivered.add(m!['n'] as int)),
    ]);
    expect(delivered, [1, 2, 3]);
    final next = await sender.encrypt({'n': 4});
    expect((await receiver.decrypt(next))?['n'], 4);
  });

  test('a failed large frame fails alone and keeps the order after it', () async {
    final sender = _context();
    final receiver = _context();
    final first = await sender.encrypt({'n': 1});
    final big = await sender.encrypt({'n': 2, 'data': 'c' * (512 * 1024)});
    final last = await sender.encrypt({'n': 3});
    final tag = big['tag'] as String;
    big['tag'] = '${tag[0] == 'A' ? 'B' : 'A'}${tag.substring(1)}';
    final delivered = <Object?>[];
    await Future.wait([
      for (final f in [first, big, last])
        receiver.decrypt(f).then((m) => delivered.add(m?['n'])),
    ]);
    expect(delivered, [1, null, 3]);
    expect(await receiver.decrypt(big), isNull);
  });

  test('the large path decrypts to the same map as the inline path', () async {
    final payload = {'data': 'd' * (60 * 1024), 'unicode': 'カラシビ', 'n': 7};
    final small = await _context().encrypt(payload);
    expect((small['ciphertext'] as String).length, lessThan(96 * 1024));
    expect(await _context().decrypt(small), payload);
    final bigPayload = {...payload, 'data': 'd' * (512 * 1024)};
    final large = await _context().encrypt(bigPayload);
    expect(await _context().decrypt(large), bigPayload);
  });
}
