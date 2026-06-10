package com.uacryptex.uacryptex

import io.flutter.embedding.engine.plugins.FlutterPlugin

/** Loads `libuacryptex_ffi.so` from jniLibs; Dart opens it via FFI. */
class UacryptexPlugin : FlutterPlugin {
    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {}

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {}
}
