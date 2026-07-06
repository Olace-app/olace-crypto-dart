/// Shared result type — real service and subwindow proxy both return
/// this. Has JSON helpers so it can cross the bridge intact.
class PendingBackupSetupResumeResult {
  const PendingBackupSetupResumeResult({
    this.completed = false,
    this.shouldRetryLater = false,
    this.needsRecovery = false,
    this.expiredOrCleared = false,
    this.errorMessage,
  });

  const PendingBackupSetupResumeResult.none()
      : completed = false,
        shouldRetryLater = false,
        needsRecovery = false,
        expiredOrCleared = false,
        errorMessage = null;

  final bool completed;
  final bool shouldRetryLater;
  final bool needsRecovery;
  final bool expiredOrCleared;
  final String? errorMessage;

  Map<String, Object?> toJson() => <String, Object?>{
        'completed': completed,
        'shouldRetryLater': shouldRetryLater,
        'needsRecovery': needsRecovery,
        'expiredOrCleared': expiredOrCleared,
        'errorMessage': errorMessage,
      };

  factory PendingBackupSetupResumeResult.fromJson(Map<String, dynamic> j) {
    return PendingBackupSetupResumeResult(
      completed: j['completed'] == true,
      shouldRetryLater: j['shouldRetryLater'] == true,
      needsRecovery: j['needsRecovery'] == true,
      expiredOrCleared: j['expiredOrCleared'] == true,
      errorMessage: j['errorMessage']?.toString(),
    );
  }
}

/// Interface for [CloudBackupSetupService] + subwindow proxy. Covers
/// the two operations UI actually invokes: finalize (first-time
/// enrollment, passes base64-encoded mk + recovery key bytes over
/// the bridge — see note in [finalizeSetupB64]) and reconcile.
abstract class CloudBackupSetupApi {
  /// Finalize fresh cloud-backup enrollment.
  ///
  /// The MK + recovery key cross the bridge base64-encoded because
  /// this is the NEW user flow: the MK was generated on the calling
  /// isolate moments before and doesn't yet exist as persisted
  /// authoritative state anywhere. On success, the leader persists
  /// the MK to the single authoritative secure store (same disk
  /// credential store either isolate would write to anyway); from
  /// then on the leader is the canonical owner.
  Future<void> finalizeSetupB64({
    required String mkB64,
    required String recoveryKeyB64,
    required String pin,
    required String userId,
    int mkVersion = 1,
  });

  Future<PendingBackupSetupResumeResult> reconcilePendingSetupIfNeeded();
}
