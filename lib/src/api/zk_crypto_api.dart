/// Contract for zero-knowledge encryption as the Olace app consumes it.
///
/// The app implements this twice: a real service in the leader process
/// (the only isolate holding the unwrapped Master Key) and a forwarding
/// proxy for secondary desktop windows. Subwindow engines never hold the
/// MK in memory; their proxy forwards every encrypt/decrypt RPC to the
/// leader.
///
/// Only the methods a subwindow legitimately needs are on this
/// interface. Master-key lifecycle (wrap/unwrap/store/load/clear)
/// stays leader-only by design — a subwindow asking for the raw MK
/// bytes would defeat the point of the leader-isolate split.
abstract class ZkCryptoApi {
  /// Encrypt a conversation payload into a `zk1` token.
  Future<String> encryptConversation(
    Map<String, dynamic> payload, {
    required String userId,
    required String conversationId,
  });

  /// Decrypt a conversation `zk1` token.
  Future<Map<String, dynamic>> decryptConversation(
    String ciphertext, {
    required String userId,
    required String conversationId,
  });

  /// Encrypt a project payload into a `zk1` token.
  Future<String> encryptProject(
    Map<String, dynamic> payload, {
    required String userId,
    required String projectId,
  });

  /// Decrypt a project `zk1` token.
  Future<Map<String, dynamic>> decryptProject(
    String ciphertext, {
    required String userId,
    required String projectId,
  });

  /// Encrypt a conversation-scoped research context payload.
  Future<String> encryptResearchContext(
    Map<String, dynamic> payload, {
    required String userId,
    required String conversationId,
  });

  /// Decrypt a research context `zk1` token.
  Future<Map<String, dynamic>> decryptResearchContext(
    String ciphertext, {
    required String userId,
    required String conversationId,
  });

  /// Encrypt the user-instructions backup payload.
  Future<String> encryptInstructions(
    Map<String, dynamic> payload, {
    required String userId,
  });

  /// Decrypt a user-instructions `zk1` token.
  Future<Map<String, dynamic>> decryptInstructions(
    String ciphertext, {
    required String userId,
  });

  /// Encrypt the single BYOK key vault for *userId*. Returns a
  /// ``"zk1:..."`` token. Payload shape:
  ///
  /// ```
  /// { "updated_at": <epoch ms>, "device_origin_id": "didv1_...",
  ///   "keys": { providerId: {"key": ..., "updated_at": ..., "device_origin": ...} },
  ///   "tombstones": { providerId: <deleted_at epoch ms> } }
  /// ```
  Future<String> encryptByokVault(
    Map<String, dynamic> payload, {
    required String userId,
  });

  /// Decrypt a BYOK key vault ciphertext for *userId*.
  Future<Map<String, dynamic>> decryptByokVault(
    String ciphertext, {
    required String userId,
  });

  /// Whether an unwrapped Master Key is currently available.
  Future<bool> hasMk();

  /// Recovery-key flow: subwindow supplies wrapped MK + recovery key
  /// and leader unwraps + stores it locally. Raw MK bytes never
  /// cross the bridge — the subwindow receives only a success flag.
  /// Inputs are base64-encoded so the bridge carries plain JSON.
  Future<bool> unwrapAndStoreMk({
    required String wrappedMkB64,
    required String recoveryKeyB64,
    required String userId,
    required int mkVersion,
  });

  /// Clear the locally stored MK (sign-out / account deletion).
  Future<void> clearMk();
}
