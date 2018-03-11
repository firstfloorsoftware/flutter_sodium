package com.firstfloorsoftware.fluttersodium;

import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.PluginRegistry.Registrar;
import static org.libsodium.jni.NaCl.sodium;

/**
 * FlutterSodiumPlugin
 */
public class FlutterSodiumPlugin implements MethodCallHandler {
  /**
   * Plugin registration.
   */
  public static void registerWith(Registrar registrar) {
    final MethodChannel channel = new MethodChannel(registrar.messenger(), "flutter_sodium");
    channel.setMethodCallHandler(new FlutterSodiumPlugin());
  }

  @Override
  public void onMethodCall(MethodCall call, Result result) {
    try{
      switch(call.method) {
        case "sodium_version_string": sodium_version_string(call, result); break;

        default: result.notImplemented(); break;
      }
    }
    catch(Exception error)
    {
      result.error("Error", call.method + " fails with " + error.getMessage(), null);
    }
  }

  private void sodium_version_string(MethodCall call, Result result)
  {
    // FIXME: sodium().sodium_version_string() throws
    // for now version is hardcoded
    result.success("1.0.16");
  }
}
