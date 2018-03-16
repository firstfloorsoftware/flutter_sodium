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
        case "crypto_auth": crypto_auth(call, result); break;
        case "crypto_auth_verify": crypto_auth_verify(call, result); break;
        case "crypto_auth_keygen": crypto_auth_keygen(call, result); break;

        case "crypto_generichash": crypto_generichash(call, result); break;
        case "crypto_generichash_init": crypto_generichash_init(call, result); break;
        case "crypto_generichash_update": crypto_generichash_update(call, result); break;
        case "crypto_generichash_final": crypto_generichash_final(call, result); break;
        case "crypto_generichash_keygen": crypto_generichash_keygen(call, result); break;

        case "crypto_pwhash": crypto_pwhash(call, result); break;
        case "crypto_pwhash_str": crypto_pwhash_str(call, result); break;
        case "crypto_pwhash_str_verify": crypto_pwhash_str_verify(call, result); break;
        case "crypto_pwhash_str_needs_rehash": crypto_pwhash_str_needs_rehash(call, result); break;

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

  private void crypto_auth(MethodCall call, Result result) throws Exception
  {
    byte[] in = call.argument("in");
    byte[] k = call.argument("k");
    byte[] out = new byte[sodium().crypto_auth_bytes()];

    requireSuccess(sodium().crypto_auth(out, in, in.length, k));
    result.success(out); 
  }

  private void crypto_auth_verify(MethodCall call, Result result)
  {
    byte[] h = call.argument("h");
    byte[] in = call.argument("in");
    byte[] k = call.argument("k");

    int ret = sodium().crypto_auth_verify(h, in, in.length, k);
    result.success(ret == 0); 
  }

  private void crypto_auth_keygen(MethodCall call, Result result)
  {
    // FIXME: crypto_auth_keygen not implemented in libsodium-jni, falling back to randombytes_buf
    byte[] k = new byte[sodium().crypto_auth_keybytes()];
    sodium().randombytes_buf(k, k.length);
    result.success(k);
  }

  private void crypto_generichash(MethodCall call, Result result) throws Exception
  {
    int outlen = call.argument("outlen");
    byte[] in = call.argument("in");
    byte[] key = call.argument("key");
    if (key == null)
    {
      key = new byte[0];
    }
    byte[] out = new byte[outlen];

    requireSuccess(sodium().crypto_generichash(out, outlen, in, in.length, key, key.length));

    result.success(out);
  }

  private void crypto_generichash_init(MethodCall call, Result result) throws Exception
  {
    byte[] key = call.argument("key");
    int outlen = call.argument("outlen");
    
    if (key == null)
    {
      key = new byte[0];
    }
    byte[] state = new byte[sodium().crypto_generichash_statebytes()];

    requireSuccess(sodium().crypto_generichash_init(state, key, key.length, outlen));

    result.success(state);
  }

  private void crypto_generichash_update(MethodCall call, Result result) throws Exception
  {
    byte[] state = call.argument("state");
    byte[] in = call.argument("in");

    requireSuccess(sodium().crypto_generichash_update(state, in, in.length));

    result.success(state);
  }

  private void crypto_generichash_final(MethodCall call, Result result) throws Exception
  {
    byte[] state = call.argument("state");
    int outlen = call.argument("outlen");
    
    byte[] out = new byte[outlen];

    requireSuccess(sodium().crypto_generichash_final(state, out, outlen));

    result.success(out);
  }

  private void crypto_generichash_keygen(MethodCall call, Result result)
  {
    // FIXME: crypto_generichash_keygen not implemented in libsodium-jni, falling back to randombytes_buf
    byte[] k = new byte[sodium().crypto_generichash_keybytes()];
    sodium().randombytes_buf(k, k.length);
    result.success(k);
  }

  private void crypto_pwhash(MethodCall call, Result result) throws Exception
  {
    int outlen = call.argument("outlen");
    byte[] passwd = call.argument("passwd");
    byte[] salt = call.argument("salt");
    int opslimit = call.argument("opslimit");
    int memlimit = call.argument("memlimit");
    int alg = call.argument("alg");

    byte[] out = new byte[outlen];

    requireSuccess(sodium().crypto_pwhash(out, outlen, passwd, passwd.length, salt, opslimit, memlimit, alg));
    result.success(out);
  }

  private void crypto_pwhash_str(MethodCall call, Result result) throws Exception
  {
    byte[] passwd = call.argument("passwd");
    int opslimit = call.argument("opslimit");
    int memlimit = call.argument("memlimit");

    byte[] out = new byte[sodium().crypto_pwhash_strbytes()];

    requireSuccess(sodium().crypto_pwhash_str(out, passwd, passwd.length, opslimit, memlimit));
    result.success(out);
  }

  private void crypto_pwhash_str_verify(MethodCall call, Result result)
  {
    byte[] str = call.argument("str");
    byte[] passwd = call.argument("passwd");

    int ret = sodium().crypto_pwhash_str_verify(str, passwd, passwd.length);

    result.success(ret == 0);
  }

  private void crypto_pwhash_str_needs_rehash(MethodCall call, Result result) throws Exception
  {
    // FIXME: crypto_pwhash_str_needs_rehash not implemented in libsodium-jni
    result.notImplemented();
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
    // FIXME: crypto_shorthash_keygen not implemented in libsodium-jni, falling back to randombytes_buf
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
    int rnd = sodium().randombytes_random();
    // convert result to unsigned long
    result.success(rnd & 0xFFFFFFFFL);
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
