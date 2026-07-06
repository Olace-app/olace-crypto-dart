/// Snapshot of one BYOK provider's local state — either a live key
/// (with the per-key LWW timestamp + origin device) or a tombstone
/// (deletion with timestamp). Returned by [BYOKKeyServiceApi.snapshotVault].
class BYOKProviderEntry {
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

  BYOKProviderEntry({
    required this.providerId,
    required this.updatedAt,
    required this.deviceOrigin,
    this.key,
    this.tombstone = false,
  });
}

/// Public surface for the BYOK (Bring Your Own Key) credential store.
///
/// Both the concrete leader-side service ([BYOKKeyService]) and the
/// subwindow proxy ([BYOKKeyServiceProxy]) implement this — call sites
/// reach it through the `byokKeys` getter on `ServiceLocator` and stay
/// isolate-agnostic.
///
/// Provider ids are the canonical lowercase ``byok_<provider>``
/// strings defined in ``Backend/services/catalog/model_taxonomy.py``:
/// ``byok_openrouter``, ``byok_together``, ``byok_moonshot``,
/// ``byok_glm``, ``byok_ollama``.
abstract class BYOKKeyServiceApi {
  /// Store a key for *providerId*. The key is written into
  /// `flutter_secure_storage` under the key
  /// ``byok_api_<providerId-without-byok-prefix>`` (so the literal
  /// secret string for ``byok_moonshot`` lives under
  /// ``byok_api_moonshot``). Empty / whitespace values are a no-op.
  Future<void> setKey(String providerId, String key);

  /// Return the stored key for *providerId*, or null if none configured.
  Future<String?> getKey(String providerId);

  /// Remove the key for *providerId*. No-op when nothing is stored.
  Future<void> deleteKey(String providerId);

  /// Return the set of provider ids that currently have a non-empty
  /// key stored. Used by the chat send pipeline to populate
  /// ``ChatRequest.byokProviders`` (only when the conversation is not
  /// in Direct Mode) and by ``_chatStreamPeek``'s hydration step.
  Future<List<String>> listConfigured();

  /// Fast probe — true iff at least one BYOK key is configured. Used
  /// by UI gating (settings indicator, etc.) without paying for the
  /// list build.
  Future<bool> hasAny();

  /// Full per-provider snapshot used by the cloud-sync vault payload
  /// builder. One entry per known provider that has ever had a key
  /// or tombstone set locally. The merge logic in CloudSyncService
  /// LWW-merges this against the remote-decrypted vault.
  Future<List<BYOKProviderEntry>> snapshotVault();

  /// Apply a merged vault back to local storage. Live keys are
  /// written (replacing or upserting); tombstoned providers have
  /// any local key deleted. The corresponding ``_ts`` /
  /// ``_tombstone_ts`` markers are updated to the entry's
  /// ``updatedAt`` so the next snapshot reflects the merged state.
  ///
  /// Returns true iff anything actually changed locally (used by
  /// the apply path to decide whether to fire a settings tick).
  Future<bool> applyVault(List<BYOKProviderEntry> merged);
}
