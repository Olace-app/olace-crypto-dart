import 'dart:async';
import 'dart:isolate';

/// Run [callback] on a worker isolate so large JSON encodes and encrypts
/// never stall the caller's isolate. Byte output is identical to running
/// inline; only the executing isolate differs.
Future<R> offloadCompute<Q, R>(FutureOr<R> Function(Q) callback, Q message) =>
    Isolate.run(() => callback(message));
