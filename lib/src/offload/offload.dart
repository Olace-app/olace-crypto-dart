/// Isolate offload seam. Crypto byte output is identical on every
/// platform; this only decides which isolate runs a large JSON encode
/// or encrypt so the UI isolate never stalls. Native offloads to a
/// worker isolate, web runs inline (the web platform has no isolates).
library;

export 'offload_io.dart' if (dart.library.js_interop) 'offload_web.dart';
