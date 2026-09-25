# Changelog

Wire compatibility rule: any change to bytes (salts, info strings, AAD,
envelope layouts, key derivation parameters) is a new minor version with
a wire compatibility note here. Never a patch release. The committed
test vectors change only alongside such a note.

## 0.2.0

Wire compatibility: adds the `zk2` envelope. Readers of 0.1.x cannot open
it, so writers must stay on `zk1` until every client reading the data has
0.2.0. Every `zk1` byte and vector is unchanged, and `zk1` is still the
default output.

- `zk2:` + base64url(nonce || AES-256-GCM(raw DEFLATE(plaintext)) || tag).
  Same per-purpose HKDF data key as `zk1`; the AAD is the `zk1` AAD plus
  `|zk2`, so relabelling an envelope between the two formats fails
  authentication.
- Opt in per call with `compress: true` on `encryptConversation`,
  `encryptProject` and `encryptResearchContext`. Every decrypt path
  (`decryptWithMk` and the typed helpers) reads both formats.
- `encryptJson` / `decryptJson`: JSON encode or parse, compression and
  AES-GCM run together on a worker isolate once a payload reaches 64 KiB
  (previously only the AES step moved). `encryptConversationSized` also
  returns the plaintext length.
- New dependency: `archive` (raw DEFLATE on web; native uses the platform
  zlib). The two interoperate, and a test pins that.
- Security note: compressing before encrypting makes ciphertext length
  depend on content. A party that can inject chosen text into a payload
  and observe envelope sizes gains a length signal it does not get from
  `zk1`. Callers decide per data class whether that trade is acceptable.
- New decrypt vectors: `conversation_zk2`, `project_zk2`,
  `research_context_zk2` (with their expected payload).

## 0.1.1

- Documentation: doc comments on the full public API, contract-oriented
  interface docs, packaging metadata, lints. No code behavior change.
- Renamed `BYOKKeyServiceApi` / `BYOKProviderEntry` to
  `ByokKeyServiceApi` / `ByokProviderEntry` (Effective Dart casing).

## 0.1.0

Initial public release, extracted verbatim from the Olace app:
zero-knowledge backup encryption (`zk1` envelopes, Master Key wrap),
PIN vault three-stage derivation, Crockford recovery keys, the E2EE
session core (byte-compatible with olace-e2ee-go, pinned by shared
vectors), and Master Key transfer with SAS number-match.
