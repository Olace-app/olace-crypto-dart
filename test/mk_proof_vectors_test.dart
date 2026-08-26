// MK possession-proof vectors: the client-side Ed25519 derivation and
// signing must interoperate with the backend verifier (pyca/cryptography).
//
// The expected values were produced by the reference Python implementation:
//   seed = HKDF-SHA256(ikm=mk, salt=b"olace-mk-proof-v1", info=user_id)
//   sk   = Ed25519PrivateKey.from_private_bytes(seed)
//   msg  = f"olace-mk-proof-v1|{user_id}|mk_proof_email_change|{nonce}"
// with mk = bytes(range(32)), user_id = "user-vector-1",
// nonce = "nonce-vector-1". Ed25519 is deterministic, so the SIGNATURE is a
// stable vector too, not just the public key. If either assertion breaks,
// the wire contract with Backend/utils/auth/phone_auth_flow_recovery.py
// broke with it.
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:olace_crypto/olace_crypto.dart';
import 'package:test/test.dart';

void main() {
  final mk = Uint8List.fromList(List<int>.generate(32, (i) => i));
  const userId = 'user-vector-1';
  const nonce = 'nonce-vector-1';
  const purpose = 'mk_proof_email_change';

  const expectedPub = '0r7C8qWjwXxrMhypYrwLnLsldtcB4PekZnBYTKIOX0w';
  const expectedSig =
      'fIV30AyPUyfZ5GiTkUeKs9Cc6mCPcim0w9mKyG-xY7IkCAPZBKvsA9HDffE77kK-'
      'BSFEQFHx22jyPSU3YQYQDw';

  test('public key matches the pyca reference vector', () async {
    expect(await ZkCrypto.mkProofPublicKeyB64(mk, userId), expectedPub);
  });

  test('signature matches the pyca reference vector', () async {
    final sig = await ZkCrypto.signMkProofChallenge(
      mk: mk,
      userId: userId,
      purpose: purpose,
      nonce: nonce,
    );
    expect(sig, expectedSig);
  });

  test('derivation is deterministic and per-user distinct', () async {
    final a = await ZkCrypto.mkProofPublicKeyB64(mk, userId);
    final b = await ZkCrypto.mkProofPublicKeyB64(mk, userId);
    final other = await ZkCrypto.mkProofPublicKeyB64(mk, 'user-vector-2');
    expect(a, b);
    expect(a, isNot(other));
  });

  test('signature verifies against the derived public key', () async {
    final keyPair = await ZkCrypto.deriveMkProofKeyPair(mk, userId);
    final publicKey = await keyPair.extractPublicKey();
    final sigB64 = await ZkCrypto.signMkProofChallenge(
      mk: mk,
      userId: userId,
      purpose: purpose,
      nonce: nonce,
    );
    final padded = sigB64 + '=' * ((4 - sigB64.length % 4) % 4);
    final ok = await Ed25519().verify(
      'olace-mk-proof-v1|$userId|$purpose|$nonce'.codeUnits,
      signature: Signature(
        Uint8List.fromList(base64Url.decode(padded)),
        publicKey: publicKey,
      ),
    );
    expect(ok, isTrue);
  });
}
