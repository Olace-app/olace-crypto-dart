import 'dart:async';
import 'dart:isolate';

Future<R> offloadCompute<Q, R>(FutureOr<R> Function(Q) callback, Q message) =>
    Isolate.run(() => callback(message));
