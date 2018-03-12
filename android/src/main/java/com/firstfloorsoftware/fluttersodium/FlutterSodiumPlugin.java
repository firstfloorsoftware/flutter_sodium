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
        case "crypto_shorthash": crypto_shorthash(call, result); break;
        case "crypto_shorthash_keygen": crypto_shorthash_keygen(call, result); break;
        
        case "randombytes_buf": randombytes_buf(call, result); break;
        case "randombytes_buf_deterministic": randombytes_buf_deterministic(call, result); break;
        case "randombytes_random": randombytes_random(call, result); break;
        case "randombytes_uniform": randombytes_uniform(call, result); break;
        case "randombytes_stir": randombytes_stir(call, result); break;
        case "randombytes_close": randombytes_close(call, result); break;

        case "sodium_version_string": sodium_version_string(call, result); break;

        default: result.notImplemented(); break;
      }
    }
    catch(Exception error)
    {
      result.error("Error", call.method + " fails with " + error.getMessage(), null);
    }
  }

  private static void requireSuccess(int ret) throws Exception
  {
    if (ret != 0)
    {
      throw new Exception("result " + ret);
    }
  }

  private void crypto_shorthash(MethodCall call, Result result) throws Exception
  {
    byte[] in = call.argument("in");
    byte[] k = call.argument("k");

    byte[] out = new byte[sodium().crypto_shorthash_bytes()];
    
    requireSuccess(sodium().crypto_shorthash(out, in, in.length, k));

    result.success(out);
  }

  private void crypto_shorthash_keygen(MethodCall call, Result result)
  {
    // FIXME: falling back to randombytes_buf, crypto_shorthash_keygen not implemented in libsodium-jni
    byte[] k = new byte[sodium().crypto_shorthash_keybytes()];
    sodium().randombytes_buf(k, k.length);
    result.success(k);
  }

  private void randombytes_buf(MethodCall call, Result result)
  {
    int size = call.argument("size");
    byte[] buf = new byte[size];
    sodium().randombytes_buf(buf, size);
    result.success(buf);
  }

  private void randombytes_buf_deterministic(MethodCall call, Result result)
  {
    // FIXME: randombytes_buf_deterministic not implemented in libsodium-jni
    result.notImplemented();
  }

  private void randombytes_random(MethodCall call, Result result)
  {
    result.success(sodium().randombytes_random());
  }

  private void randombytes_uniform(MethodCall call, Result result)
  {
    int upper_bound = call.argument("upper_bound");
    result.success(sodium().randombytes_uniform(upper_bound));
  }

  private void randombytes_stir(MethodCall call, Result result)
  {
    sodium().randombytes_stir();
    result.success(null);
  }

  private void randombytes_close(MethodCall call, Result result) throws Exception
  {
    requireSuccess(sodium().randombytes_close());
  }

  private void sodium_version_string(MethodCall call, Result result)
  {
    // FIXME: sodium_version_string throws in libsodium-jni
    // for now version is hardcoded
    result.success("1.0.16");
  }
}
