/// Abstract interface implemented by both [ZkCryptoService] (leader)
/// and [ZkCryptoProxy] (subwindow). Subwindow engines never hold the
/// master key in memory — their proxy forwards every encrypt/decrypt
/// RPC to the leader, which is the only isolate with access to the
/// unwrapped MK.
///
/// Only the methods a subwindow legitimately needs are on this
/// interface. Master-key lifecycle (wrap/unwrap/store/load/clear)
/// stays leader-only by design — a subwindow asking for the raw MK
/// bytes would defeat the point of the leader-isolate split.
abstract class ZkCryptoApi {
  Future<String> encryptConversation(
    Map<String, dynamic> payload, {
    required String userId,
    required String conversationId,
  });

  Future<Map<String, dynamic>> decryptConversation(
    String ciphertext, {
    required String userId,
    required String conversationId,
  });

  Future<String> encryptProject(
    Map<String, dynamic> payload, {
    required String userId,
    required String projectId,
  });

  Future<Map<String, dynamic>> decryptProject(
    String ciphertext, {
    required String userId,
    required String projectId,
  });

  Future<String> encryptResearchContext(
    Map<String, dynamic> payload, {
    required String userId,
    required String conversationId,
  });

  Future<Map<String, dynamic>> decryptResearchContext(
    String ciphertext, {
    required String userId,
    required String conversationId,
  });

  Future<String> encryptInstructions(
    Map<String, dynamic> payload, {
    required String userId,
  });

  Future<Map<String, dynamic>> decryptInstructions(
    String ciphertext, {
    required String userId,
  });

  /// Encrypt the single BYOK key vault for *userId*. Payload structure
  /// is documented in `project_byok_client_executor.md`. Returns a
  /// ``"zk1:..."`` token.
  Future<String> encryptByokVault(
    Map<String, dynamic> payload, {
    required String userId,
  });

  /// Decrypt a BYOK key vault ciphertext for *userId*.
  Future<Map<String, dynamic>> decryptByokVault(
    String ciphertext, {
    required String userId,
  });

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
