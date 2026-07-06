import 'dart:async';

Future<R> offloadCompute<Q, R>(
        FutureOr<R> Function(Q) callback, Q message) async =>
    await callback(message);
