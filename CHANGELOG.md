# Changelog

Wire compatibility rule: any change to bytes (salts, info strings, AAD,
envelope layouts, key derivation parameters) is a new minor version with
a wire compatibility note here. Never a patch release. The committed
test vectors change only alongside such a note.

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
