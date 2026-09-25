/// Raw DEFLATE (RFC 1951) for the `zk2` envelope. Native uses the
/// platform zlib; web uses the pure-Dart codec from `package:archive`.
/// Either side inflates what the other deflates.
library;

export 'deflate_io.dart' if (dart.library.js_interop) 'deflate_web.dart';
