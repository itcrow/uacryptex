import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import 'bindings.dart';

DynamicLibrary? _loaded;

/// Open the uacryptex native library (cached).
DynamicLibrary openUacryptexLibrary({String? explicitPath}) {
  if (_loaded != null) return _loaded!;
  _loaded = _open(explicitPath);
  return _loaded!;
}

DynamicLibrary _open(String? explicitPath) {
  if (explicitPath != null && explicitPath.isNotEmpty) {
    return DynamicLibrary.open(explicitPath);
  }
  final env = Platform.environment['UACRYPTEX_LIB'];
  if (env != null && env.isNotEmpty) {
    return DynamicLibrary.open(env);
  }

  for (final candidate in _libCandidates()) {
    if (File(candidate).existsSync()) {
      return DynamicLibrary.open(candidate);
    }
  }

  if (Platform.isAndroid) {
    return DynamicLibrary.open('libuacryptex_ffi.so');
  }
  if (Platform.isIOS) {
    return DynamicLibrary.process();
  }

  final name = _libFileName(_osName());
  throw StateError(
    'uacryptex native library not found. Tried: ${_libCandidates().join(", ")}. '
    'Run ./scripts/build-ffi.sh && ./scripts/sync-native-libs.sh from the repo root, '
    'or set UACRYPTEX_LIB.',
  );
}

List<String> _libCandidates() {
  final os = _osName();
  final arch = _archName();
  final name = _libFileName(os);
  final rel = ['native', 'lib', os, arch, 'shared', name];
  final paths = <String>[];

  void addJoin(String base) {
    paths.add(_joinAll([base, ...rel]));
    paths.add(_joinAll([base, 'dart', 'uacryptex', ...rel]));
  }

  addJoin(Directory.current.path);
  final script = Platform.script.toFilePath();
  var dir = File(script).parent.path;
  for (var i = 0; i < 8; i++) {
    addJoin(dir);
    dir = Directory(dir).parent.path;
  }
  return paths;
}

String _joinAll(List<String> parts) {
  return parts.join(Platform.pathSeparator);
}

String _osName() {
  if (Platform.isLinux) return 'linux';
  if (Platform.isMacOS) return 'darwin';
  if (Platform.isWindows) return 'windows';
  if (Platform.isAndroid) return 'linux';
  if (Platform.isIOS) return 'darwin';
  return 'linux';
}

String _archName() {
  switch (Abi.current()) {
    case Abi.linuxArm64:
    case Abi.macosArm64:
    case Abi.androidArm64:
    case Abi.windowsArm64:
    case Abi.iosArm64:
      return 'arm64';
    default:
      return 'amd64';
  }
}

String _libFileName(String os) {
  if (os == 'windows') return 'uacryptex_ffi.dll';
  if (os == 'darwin') return 'libuacryptex_ffi.dylib';
  return 'libuacryptex_ffi.so';
}
