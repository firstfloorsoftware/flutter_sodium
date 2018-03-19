package com.firstfloorsoftware.fluttersodium;

import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.PluginRegistry.Registrar;
import java.util.HashMap;
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

        case "crypto_box_seed_keypair": crypto_box_seed_keypair(call, result); break;
        case "crypto_box_keypair": crypto_box_keypair(call, result); break;
        case "crypto_box_easy": crypto_box_easy(call, result); break;
        case "crypto_box_open_easy": crypto_box_open_easy(call, result); break;
        case "crypto_box_detached": crypto_box_detached(call, result); break;
        case "crypto_box_open_detached": crypto_box_open_detached(call, result); break;
        case "crypto_box_beforenm": crypto_box_beforenm(call, result); break;
        case "crypto_box_easy_afternm": crypto_box_easy_afternm(call, result); break;
        case "crypto_box_open_easy_afternm": crypto_box_open_easy_afternm(call, result); break;
        case "crypto_box_detached_afternm": crypto_box_detached_afternm(call, result); break;
        case "crypto_box_open_detached_afternm": crypto_box_open_detached_afternm(call, result); break;

        case "crypto_box_seal": crypto_box_seal(call, result); break;
        case "crypto_box_seal_open": crypto_box_seal_open(call, result); break;

        case "crypto_generichash": crypto_generichash(call, result); break;
        case "crypto_generichash_init": crypto_generichash_init(call, result); break;
        case "crypto_generichash_update": crypto_generichash_update(call, result); break;
        case "crypto_generichash_final": crypto_generichash_final(call, result); break;
        case "crypto_generichash_keygen": crypto_generichash_keygen(call, result); break;

        case "crypto_kdf_keygen": crypto_kdf_keygen(call, result); break;
        case "crypto_kdf_derive_from_key": crypto_kdf_derive_from_key(call, result); break;

        case "crypto_kx_keypair": crypto_kx_keypair(call, result); break;
        case "crypto_kx_seed_keypair": crypto_kx_seed_keypair(call, result); break;
        case "crypto_kx_client_session_keys": crypto_kx_client_session_keys(call, result); break;
        case "crypto_kx_server_session_keys": crypto_kx_server_session_keys(call, result); break;

        case "crypto_onetimeauth": crypto_onetimeauth(call, result); break;
        case "crypto_onetimeauth_verify": crypto_onetimeauth_verify(call, result); break;
        case "crypto_onetimeauth_init": crypto_onetimeauth_init(call, result); break;
        case "crypto_onetimeauth_update": crypto_onetimeauth_update(call, result); break;
        case "crypto_onetimeauth_final": crypto_onetimeauth_final(call, result); break;
        case "crypto_onetimeauth_keygen": crypto_onetimeauth_keygen(call, result); break;

        case "crypto_pwhash": crypto_pwhash(call, result); break;
        case "crypto_pwhash_str": crypto_pwhash_str(call, result); break;
        case "crypto_pwhash_str_verify": crypto_pwhash_str_verify(call, result); break;
        case "crypto_pwhash_str_needs_rehash": crypto_pwhash_str_needs_rehash(call, result); break;

        case "crypto_secretbox_easy": crypto_secretbox_easy(call, result); break;
        case "crypto_secretbox_open_easy": crypto_secretbox_open_easy(call, result); break;
        case "crypto_secretbox_detached": crypto_secretbox_detached(call, result); break;
        case "crypto_secretbox_open_detached": crypto_secretbox_open_detached(call, result); break;
        case "crypto_secretbox_keygen": crypto_secretbox_keygen(call, result); break;

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

  private void crypto_box_seed_keypair(MethodCall call, Result result) throws Exception
  {
    byte[] seed = call.argument("seed");
    byte[] pk = new byte[sodium().crypto_box_publickeybytes()];
    byte[] sk = new byte[sodium().crypto_box_secretkeybytes()];

    requireSuccess(sodium().crypto_box_seed_keypair(pk, sk, seed));
    HashMap map = new HashMap();
    map.put("pk", pk);
    map.put("sk", sk);
    result.success(map);
  }

  private void crypto_box_keypair(MethodCall call, Result result) throws Exception
  {
    byte[] pk = new byte[sodium().crypto_box_publickeybytes()];
    byte[] sk = new byte[sodium().crypto_box_secretkeybytes()];

    requireSuccess(sodium().crypto_box_keypair(pk, sk));
    HashMap map = new HashMap();
    map.put("pk", pk);
    map.put("sk", sk);
    result.success(map);
  }

  private void crypto_box_easy(MethodCall call, Result result) throws Exception
  {
    byte[] m = call.argument("m");
    byte[] n = call.argument("n");
    byte[] pk = call.argument("pk");
    byte[] sk = call.argument("sk");
    byte[] c = new byte[sodium().crypto_box_macbytes() + m.length];

    requireSuccess(sodium().crypto_box_easy(c, m, m.length, n, pk, sk));
    result.success(c);
  }

  private void crypto_box_open_easy(MethodCall call, Result result) throws Exception
  {
    byte[] c = call.argument("c");
    byte[] n = call.argument("n");
    byte[] pk = call.argument("pk");
    byte[] sk = call.argument("sk");
    byte[] m = new byte[c.length - sodium().crypto_box_macbytes()];

    requireSuccess(sodium().crypto_box_open_easy(m, c, c.length, n, pk, sk));
    result.success(m);
  }

  private void crypto_box_detached(MethodCall call, Result result) throws Exception
  {
    byte[] m = call.argument("m");
    byte[] n = call.argument("n");
    byte[] pk = call.argument("pk");
    byte[] sk = call.argument("sk");

    byte[] c = new byte[m.length];
    byte[] mac = new byte[sodium().crypto_box_macbytes()];

    requireSuccess(sodium().crypto_box_detached(c, mac, m, m.length, n, pk, sk));

    HashMap map = new HashMap();
    map.put("c", c);
    map.put("mac", mac);
    result.success(map);
  }

  private void crypto_box_open_detached(MethodCall call, Result result) throws Exception
  {
    byte[] c = call.argument("c");
    byte[] mac = call.argument("mac");
    byte[] n = call.argument("n");
    byte[] pk = call.argument("pk");
    byte[] sk = call.argument("sk");

    byte[] m = new byte[c.length];

    requireSuccess(sodium().crypto_box_open_detached(m, c, mac, c.length, n, pk, sk));

    result.success(m);
  }

  private void crypto_box_beforenm(MethodCall call, Result result) throws Exception
  {
    byte[] pk = call.argument("pk");
    byte[] sk = call.argument("sk");

    byte[] k = new byte[sodium().crypto_box_beforenmbytes()];

    requireSuccess(sodium().crypto_box_beforenm(k, pk, sk));

    result.success(k);
  }

  private void crypto_box_easy_afternm(MethodCall call, Result result) throws Exception
  {
    byte[] m = call.argument("m");
    byte[] n = call.argument("n");
    byte[] k = call.argument("k");
    byte[] c = new byte[sodium().crypto_box_macbytes() + m.length];

    requireSuccess(sodium().crypto_box_easy_afternm(c, m, m.length, n, k));
    result.success(c);
  }

  private void crypto_box_open_easy_afternm(MethodCall call, Result result) throws Exception
  {
    byte[] c = call.argument("c");
    byte[] n = call.argument("n");
    byte[] k = call.argument("k");
    byte[] m = new byte[c.length - sodium().crypto_box_macbytes()];

    requireSuccess(sodium().crypto_box_open_easy_afternm(m, c, c.length, n, k));
    result.success(m);
  }

  private void crypto_box_detached_afternm(MethodCall call, Result result) throws Exception
  {
    byte[] m = call.argument("m");
    byte[] n = call.argument("n");
    byte[] k = call.argument("k");

    byte[] c = new byte[m.length];
    byte[] mac = new byte[sodium().crypto_box_macbytes()];

    requireSuccess(sodium().crypto_box_detached_afternm(c, mac, m, m.length, n, k));

    HashMap map = new HashMap();
    map.put("c", c);
    map.put("mac", mac);
    result.success(map);
  }

  private void crypto_box_open_detached_afternm(MethodCall call, Result result) throws Exception
  {
    byte[] c = call.argument("c");
    byte[] mac = call.argument("mac");
    byte[] n = call.argument("n");
    byte[] k = call.argument("k");

    byte[] m = new byte[c.length];

    requireSuccess(sodium().crypto_box_open_detached_afternm(m, c, mac, c.length, n, k));

    result.success(m);
  }

  private void crypto_box_seal(MethodCall call, Result result) throws Exception
  {
    byte[] m = call.argument("m");
    byte[] pk = call.argument("pk");

    byte[] c = new byte[sodium().crypto_box_sealbytes() + m.length];

    requireSuccess(sodium().crypto_box_seal(c, m, m.length, pk));

    result.success(c);
  }

  private void crypto_box_seal_open(MethodCall call, Result result) throws Exception
  {
    byte[] c = call.argument("c");
    byte[] pk = call.argument("pk");
    byte[] sk = call.argument("sk");

    byte[] m = new byte[c.length - sodium().crypto_box_sealbytes()];

    requireSuccess(sodium().crypto_box_seal_open(m, c, c.length, pk, sk));

    result.success(m);
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

  private void crypto_kdf_keygen(MethodCall call, Result result)
  {
    // FIXME: crypto_kdf_keygen not implemented in libsodium-jni
    result.notImplemented();
  }

  private void crypto_kdf_derive_from_key(MethodCall call, Result result)
  {
    // FIXME: crypto_kdf_derive_from_key not implemented in libsodium-jni
    result.notImplemented();
  }

  private void crypto_kx_keypair(MethodCall call, Result result) throws Exception
  {
    byte[] pk = new byte[32];
    byte[] sk = new byte[32];

    requireSuccess(sodium().crypto_kx_keypair(pk, sk));
    HashMap map = new HashMap();
    map.put("pk", pk);
    map.put("sk", sk);
    result.success(map);
  }

  private void crypto_kx_seed_keypair(MethodCall call, Result result) throws Exception
  {
    byte[] seed = call.argument("seed");

    byte[] pk = new byte[32];
    byte[] sk = new byte[32];

    requireSuccess(sodium().crypto_kx_seed_keypair(pk, sk, seed));
    HashMap map = new HashMap();
    map.put("pk", pk);
    map.put("sk", sk);
    result.success(map);
  }

  private void crypto_kx_client_session_keys(MethodCall call, Result result) throws Exception
  {
    byte[] client_pk = call.argument("client_pk");
    byte[] client_sk = call.argument("client_sk");
    byte[] server_pk = call.argument("server_pk");
    
    byte[] rx = new byte[32];
    byte[] tx = new byte[32];
    
    requireSuccess(sodium().crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk));
    HashMap map = new HashMap();
    map.put("rx", rx);
    map.put("tx", tx);
    result.success(map);
  }

  private void crypto_kx_server_session_keys(MethodCall call, Result result) throws Exception
  {
    byte[] server_pk = call.argument("server_pk");
    byte[] server_sk = call.argument("server_sk");
    byte[] client_pk = call.argument("client_pk");
    
    byte[] rx = new byte[32];
    byte[] tx = new byte[32];
    
    requireSuccess(sodium().crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk));
    HashMap map = new HashMap();
    map.put("rx", rx);
    map.put("tx", tx);
    result.success(map);
  }

  private void crypto_onetimeauth(MethodCall call, Result result) throws Exception
  {
    byte[] in = call.argument("in");
    byte[] k = call.argument("k");

    byte[] out = new byte[sodium().crypto_onetimeauth_bytes()];
    requireSuccess(sodium().crypto_onetimeauth(out, in, in.length, k));
    result.success(out);
  }

  private void crypto_onetimeauth_verify(MethodCall call, Result result)
  {
    byte[] h = call.argument("h");
    byte[] in = call.argument("in");
    byte[] k = call.argument("k");

    int ret = sodium().crypto_onetimeauth_verify(h, in, in.length, k);
    result.success(ret == 0);
  }

  private void crypto_onetimeauth_init(MethodCall call, Result result) throws Exception
  {
    byte[] key = call.argument("key");
    byte[] state = new byte[sodium().crypto_onetimeauth_statebytes()];

    requireSuccess(sodium().crypto_onetimeauth_init(state, key));

    result.success(state);
  }

  private void crypto_onetimeauth_update(MethodCall call, Result result) throws Exception
  {
    byte[] state = call.argument("state");
    byte[] in = call.argument("in");

    requireSuccess(sodium().crypto_onetimeauth_update(state, in, in.length));

    result.success(state);
  }

  private void crypto_onetimeauth_final(MethodCall call, Result result) throws Exception
  {
    byte[] state = call.argument("state");    
    byte[] out = new byte[sodium().crypto_onetimeauth_bytes()];

    requireSuccess(sodium().crypto_onetimeauth_final(state, out));

    result.success(out);
  }

  private void crypto_onetimeauth_keygen(MethodCall call, Result result)
  {
    // FIXME: crypto_onetimeauth_keygen not implemented in libsodium-jni, falling back to randombytes_buf
    byte[] k = new byte[sodium().crypto_onetimeauth_keybytes()];
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

  private void crypto_secretbox_easy(MethodCall call, Result result) throws Exception
  {
    byte[] m = call.argument("m");
    byte[] n = call.argument("n");
    byte[] k = call.argument("k");
    byte[] c = new byte[sodium().crypto_secretbox_macbytes() + m.length];

    requireSuccess(sodium().crypto_secretbox_easy(c, m, m.length, n, k));
    result.success(c);
  }

  private void crypto_secretbox_open_easy(MethodCall call, Result result) throws Exception
  {
    byte[] c = call.argument("c");
    byte[] n = call.argument("n");
    byte[] k = call.argument("k");
    byte[] m = new byte[c.length - sodium().crypto_secretbox_macbytes()];

    requireSuccess(sodium().crypto_secretbox_open_easy(m, c, c.length, n, k));
    result.success(m);
  }

  private void crypto_secretbox_detached(MethodCall call, Result result) throws Exception
  {
    byte[] m = call.argument("m");
    byte[] n = call.argument("n");
    byte[] k = call.argument("k");
    byte[] c = new byte[m.length];
    byte[] mac = new byte[sodium().crypto_secretbox_macbytes()];

    requireSuccess(sodium().crypto_secretbox_detached(c, mac, m, m.length, n, k));

    HashMap map = new HashMap();
    map.put("c", c);
    map.put("mac", mac);
    result.success(map);
  }

  private void crypto_secretbox_open_detached(MethodCall call, Result result) throws Exception
  {
    byte[] c = call.argument("c");
    byte[] mac = call.argument("mac");
    byte[] n = call.argument("n");
    byte[] k = call.argument("k");
    byte[] m = new byte[c.length];

    requireSuccess(sodium().crypto_secretbox_open_detached(m, c, mac, c.length, n, k));

    result.success(m);
  }

  private void crypto_secretbox_keygen(MethodCall call, Result result)
  {
    // FIXME: crypto_secretbox_keygen not implemented in libsodium-jni, falling back to randombytes_buf
    byte[] k = new byte[sodium().crypto_secretbox_keybytes()];
    sodium().randombytes_buf(k, k.length);
    result.success(k);
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
