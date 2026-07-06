/// Shared result type — real service and subwindow proxy both return
/// this. Has JSON helpers so it can cross the bridge intact.
class PendingBackupSetupResumeResult {
  /// Creates a result; all flags default to false.
  const PendingBackupSetupResumeResult({
    this.completed = false,
    this.shouldRetryLater = false,
    this.needsRecovery = false,
    this.expiredOrCleared = false,
    this.errorMessage,
  });

  /// The "nothing pending, nothing done" result.
  const PendingBackupSetupResumeResult.none()
      : completed = false,
        shouldRetryLater = false,
        needsRecovery = false,
        expiredOrCleared = false,
        errorMessage = null;

  /// A pending enrollment was found and completed.
  final bool completed;

  /// A transient failure occurred; the caller should retry later.
  final bool shouldRetryLater;

  /// The pending record cannot complete without the user re-entering
  /// credentials (Recovery Key or PIN).
  final bool needsRecovery;

  /// The pending record expired server-side or was cleared; nothing to do.
  final bool expiredOrCleared;

  /// Human-readable error, when any step failed.
  final String? errorMessage;

  /// JSON form for crossing the window bridge.
  Map<String, Object?> toJson() => <String, Object?>{
        'completed': completed,
        'shouldRetryLater': shouldRetryLater,
        'needsRecovery': needsRecovery,
        'expiredOrCleared': expiredOrCleared,
        'errorMessage': errorMessage,
      };

  /// Inverse of [toJson].
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

/// Interface for the app's backup setup service + subwindow proxy. Covers
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

  /// Resume an interrupted enrollment if a pending record exists.
  Future<PendingBackupSetupResumeResult> reconcilePendingSetupIfNeeded();
}
