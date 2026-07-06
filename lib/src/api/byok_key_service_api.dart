/// Snapshot of one BYOK provider's local state: either a live key
/// (with the per-key last-write-wins timestamp and origin device) or a
/// tombstone (deletion with timestamp). Returned by
/// [ByokKeyServiceApi.snapshotVault].
class ByokProviderEntry {
  /// Canonical provider id (`byok_<provider>`).
  final String providerId;

  /// The literal API key. NULL when [tombstone] is set.
  final String? key;

  /// Epoch milliseconds when the key was last set OR deleted.
  final int updatedAt;

  /// Canonical device id (didv1_...) where the most recent
  /// set/delete happened. Empty when not yet known.
  final String deviceOrigin;

  /// True iff this entry represents a deletion (no live key).
  final bool tombstone;

  /// Creates a snapshot entry; see [ByokKeyServiceApi.snapshotVault].
  ByokProviderEntry({
    required this.providerId,
    required this.updatedAt,
    required this.deviceOrigin,
    this.key,
    this.tombstone = false,
  });
}

/// Contract for the BYOK (Bring Your Own Key) credential store.
///
/// This interface is published so the key-custody promise is auditable:
/// provider API keys live in the device's secure storage and reach the
/// provider directly from the device. They are never sent to Olace
/// servers in plaintext; the only form that leaves the device is the
/// vault ciphertext produced by `ZkCrypto.encryptByokVault`, encrypted
/// under the user's Master Key.
///
/// The Olace app implements it twice: a real service in the process
/// that owns secure storage, and a forwarding proxy for secondary
/// desktop windows, so key bytes never cross window boundaries.
///
/// Provider ids are canonical lowercase `byok_<provider>` strings, for
/// example `byok_openrouter`, `byok_together`, `byok_moonshot`,
/// `byok_glm`, `byok_ollama`.
abstract class ByokKeyServiceApi {
  /// Store a key for *providerId* in the device's secure storage.
  /// Empty / whitespace values are a no-op.
  Future<void> setKey(String providerId, String key);

  /// Return the stored key for *providerId*, or null if none configured.
  Future<String?> getKey(String providerId);

  /// Remove the key for *providerId*. No-op when nothing is stored.
  Future<void> deleteKey(String providerId);

  /// Return the set of provider ids that currently have a non-empty
  /// key stored. Lets callers route requests to configured providers
  /// without ever reading the key bytes.
  Future<List<String>> listConfigured();

  /// Fast probe: true iff at least one BYOK key is configured. For UI
  /// gating without paying for the list build.
  Future<bool> hasAny();

  /// Full per-provider snapshot used to build the encrypted sync vault.
  /// One entry per known provider that has ever had a key or tombstone
  /// set locally. The caller last-write-wins-merges this against the
  /// vault decrypted from the other devices.
  Future<List<ByokProviderEntry>> snapshotVault();

  /// Apply a merged vault back to local storage. Live keys are written
  /// (replacing or upserting); tombstoned providers have any local key
  /// deleted. Per-entry timestamps are updated to the entry's
  /// [ByokProviderEntry.updatedAt] so the next snapshot reflects the
  /// merged state.
  ///
  /// Returns true iff anything actually changed locally.
  Future<bool> applyVault(List<ByokProviderEntry> merged);
}
