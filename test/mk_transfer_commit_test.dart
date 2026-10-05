// Commit-then-reveal for the MK transfer: the requester commits to its
// ephemeral key before the responder reveals its own, so a relay cannot pick
// a substitute key after seeing both real ones.
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:olace_crypto/olace_crypto.dart';
import 'package:test/test.dart';

void main() {
  const transferId = 'transfer-vector-1';

  Future<SimplePublicKey> freshKey() async =>
      (await X25519().newKeyPair()).extractPublicKey();

  test('a commitment opens with its own key and nonce', () async {
    final pub = await freshKey();
    final c = await MkTransferCrypto.commitRequesterKey(
      requesterEphemeralPub: pub,
      transferId: transferId,
    );
    expect(
      await MkTransferCrypto.verifyRequesterCommit(
        commit: c.commit,
        requesterEphemeralPubB64: base64Encode(pub.bytes),
        nonceB64: c.nonce,
        transferId: transferId,
      ),
      isTrue,
    );
  });

  test('a different key, nonce or transfer id does not open it', () async {
    final pub = await freshKey();
    final other = await freshKey();
    final c = await MkTransferCrypto.commitRequesterKey(
      requesterEphemeralPub: pub,
      transferId: transferId,
    );
    final otherNonce = base64Url.encode(List<int>.filled(32, 7));
    Future<bool> opens(String pubB64, String nonce, String tid) =>
        MkTransferCrypto.verifyRequesterCommit(
          commit: c.commit,
          requesterEphemeralPubB64: pubB64,
          nonceB64: nonce,
          transferId: tid,
        );
    expect(
      await opens(base64Encode(other.bytes), c.nonce, transferId),
      isFalse,
    );
    expect(
      await opens(base64Encode(pub.bytes), otherNonce, transferId),
      isFalse,
    );
    expect(
      await opens(base64Encode(pub.bytes), c.nonce, 'transfer-vector-2'),
      isFalse,
    );
  });

  test('malformed input is false, never a throw', () async {
    final pub = await freshKey();
    final c = await MkTransferCrypto.commitRequesterKey(
      requesterEphemeralPub: pub,
      transferId: transferId,
    );
    for (final bad in [
      '',
      'not base64 !!',
      base64Url.encode([1, 2, 3])
    ]) {
      expect(
        await MkTransferCrypto.verifyRequesterCommit(
          commit: c.commit,
          requesterEphemeralPubB64: bad,
          nonceB64: c.nonce,
          transferId: transferId,
        ),
        isFalse,
      );
    }
  });

  test('the digest bytes are pinned', () async {
    final digest = await MkTransferCrypto.commitDigest(
      requesterPublicKey: Uint8List.fromList(List<int>.generate(32, (i) => i)),
      nonce: Uint8List.fromList(List<int>.generate(32, (i) => 255 - i)),
      transferId: transferId,
    );
    expect(
      base64Url.encode(digest),
      'M2kb6unXQiqfVc404IpEi6_6K9VShe8up1WvtU5gW_g=',
    );
  });
}
