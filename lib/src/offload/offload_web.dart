import 'dart:async';

/// Web has no isolates: run [callback] inline. Byte output is identical
/// to the native worker-isolate path.
Future<R> offloadCompute<Q, R>(
        FutureOr<R> Function(Q) callback, Q message) async =>
    await callback(message);
