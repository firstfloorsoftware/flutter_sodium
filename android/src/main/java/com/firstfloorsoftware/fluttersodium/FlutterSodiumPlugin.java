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
public class FlutterSodiumPlugin implements MethodCallHandler, CryptoTask {
    /**
     * Plugin registration.
     */
    public static void registerWith(Registrar registrar) {
        final MethodChannel channel = new MethodChannel(registrar.messenger(), "flutter_sodium");
        channel.setMethodCallHandler(new FlutterSodiumPlugin());
    }

    @Override
    public void onMethodCall(MethodCall call, Result result) {
        // run task on UI or background thread based on argument 'bgThread'
        Boolean bgThread = call.argument("bgThread");
        if (bgThread != null && bgThread) {
            // run on background thread using AsyncTask
            new CryptoAsyncTask(this, result).execute(call);
        } else {
            // run on UI thread
            try {
                result.success(execute(call));
            } catch (Exception e) {
                setError(result, e);
            }
        }
    }

    public static void setError(Result result, Exception error) {
        if (error instanceof UnsupportedOperationException) {
            result.notImplemented();
        } else {
            result.error("CryptoError", error.getMessage(), null);
        }
    }

    public Object execute(MethodCall call) throws Exception {
        switch (call.method) {
            case "crypto_aead_chacha20poly1305_encrypt":
                return crypto_aead_chacha20poly1305_encrypt(call);
            case "crypto_aead_chacha20poly1305_decrypt":
                return crypto_aead_chacha20poly1305_decrypt(call);
            case "crypto_aead_chacha20poly1305_encrypt_detached":
                return crypto_aead_chacha20poly1305_encrypt_detached(call);
            case "crypto_aead_chacha20poly1305_decrypt_detached":
                return crypto_aead_chacha20poly1305_decrypt_detached(call);
            case "crypto_aead_chacha20poly1305_keygen":
                return crypto_aead_chacha20poly1305_keygen(call);

            case "crypto_aead_chacha20poly1305_ietf_encrypt":
                return crypto_aead_chacha20poly1305_ietf_encrypt(call);
            case "crypto_aead_chacha20poly1305_ietf_decrypt":
                return crypto_aead_chacha20poly1305_ietf_decrypt(call);
            case "crypto_aead_chacha20poly1305_ietf_encrypt_detached":
                return crypto_aead_chacha20poly1305_ietf_encrypt_detached(call);
            case "crypto_aead_chacha20poly1305_ietf_decrypt_detached":
                return crypto_aead_chacha20poly1305_ietf_decrypt_detached(call);
            case "crypto_aead_chacha20poly1305_ietf_keygen":
                return crypto_aead_chacha20poly1305_ietf_keygen(call);

            case "crypto_aead_xchacha20poly1305_ietf_encrypt":
                return crypto_aead_xchacha20poly1305_ietf_encrypt(call);
            case "crypto_aead_xchacha20poly1305_ietf_decrypt":
                return crypto_aead_xchacha20poly1305_ietf_decrypt(call);
            case "crypto_aead_xchacha20poly1305_ietf_encrypt_detached":
                return crypto_aead_xchacha20poly1305_ietf_encrypt_detached(call);
            case "crypto_aead_xchacha20poly1305_ietf_decrypt_detached":
                return crypto_aead_xchacha20poly1305_ietf_decrypt_detached(call);
            case "crypto_aead_xchacha20poly1305_ietf_keygen":
                return crypto_aead_xchacha20poly1305_ietf_keygen(call);

            case "crypto_auth":
                return crypto_auth(call);
            case "crypto_auth_verify":
                return crypto_auth_verify(call);
            case "crypto_auth_keygen":
                return crypto_auth_keygen(call);

            case "crypto_box_seed_keypair":
                return crypto_box_seed_keypair(call);
            case "crypto_box_keypair":
                return crypto_box_keypair(call);
            case "crypto_box_easy":
                return crypto_box_easy(call);
            case "crypto_box_open_easy":
                return crypto_box_open_easy(call);
            case "crypto_box_detached":
                return crypto_box_detached(call);
            case "crypto_box_open_detached":
                return crypto_box_open_detached(call);
            case "crypto_box_beforenm":
                return crypto_box_beforenm(call);
            case "crypto_box_easy_afternm":
                return crypto_box_easy_afternm(call);
            case "crypto_box_open_easy_afternm":
                return crypto_box_open_easy_afternm(call);
            case "crypto_box_detached_afternm":
                return crypto_box_detached_afternm(call);
            case "crypto_box_open_detached_afternm":
                return crypto_box_open_detached_afternm(call);

            case "crypto_box_seal":
                return crypto_box_seal(call);
            case "crypto_box_seal_open":
                return crypto_box_seal_open(call);

            case "crypto_box_curve25519xchacha20poly1305_seed_keypair":
                return crypto_box_curve25519xchacha20poly1305_seed_keypair(call);
            case "crypto_box_curve25519xchacha20poly1305_keypair":
                return crypto_box_curve25519xchacha20poly1305_keypair(call);
            case "crypto_box_curve25519xchacha20poly1305_easy":
                return crypto_box_curve25519xchacha20poly1305_easy(call);
            case "crypto_box_curve25519xchacha20poly1305_open_easy":
                return crypto_box_curve25519xchacha20poly1305_open_easy(call);
            case "crypto_box_curve25519xchacha20poly1305_detached":
                return crypto_box_curve25519xchacha20poly1305_detached(call);
            case "crypto_box_curve25519xchacha20poly1305_open_detached":
                return crypto_box_curve25519xchacha20poly1305_open_detached(call);
            case "crypto_box_curve25519xchacha20poly1305_beforenm":
                return crypto_box_curve25519xchacha20poly1305_beforenm(call);
            case "crypto_box_curve25519xchacha20poly1305_easy_afternm":
                return crypto_box_curve25519xchacha20poly1305_easy_afternm(call);
            case "crypto_box_curve25519xchacha20poly1305_open_easy_afternm":
                return crypto_box_curve25519xchacha20poly1305_open_easy_afternm(call);
            case "crypto_box_curve25519xchacha20poly1305_detached_afternm":
                return crypto_box_curve25519xchacha20poly1305_detached_afternm(call);
            case "crypto_box_curve25519xchacha20poly1305_open_detached_afternm":
                return crypto_box_curve25519xchacha20poly1305_open_detached_afternm(call);

            case "crypto_box_curve25519xchacha20poly1305_seal":
                return crypto_box_curve25519xchacha20poly1305_seal(call);
            case "crypto_box_curve25519xchacha20poly1305_seal_open":
                return crypto_box_curve25519xchacha20poly1305_seal_open(call);

            case "crypto_generichash":
                return crypto_generichash(call);
            case "crypto_generichash_init":
                return crypto_generichash_init(call);
            case "crypto_generichash_update":
                return crypto_generichash_update(call);
            case "crypto_generichash_final":
                return crypto_generichash_final(call);
            case "crypto_generichash_keygen":
                return crypto_generichash_keygen(call);

            case "crypto_kdf_keygen":
                return crypto_kdf_keygen(call);
            case "crypto_kdf_derive_from_key":
                return crypto_kdf_derive_from_key(call);

            case "crypto_kx_keypair":
                return crypto_kx_keypair(call);
            case "crypto_kx_seed_keypair":
                return crypto_kx_seed_keypair(call);
            case "crypto_kx_client_session_keys":
                return crypto_kx_client_session_keys(call);
            case "crypto_kx_server_session_keys":
                return crypto_kx_server_session_keys(call);

            case "crypto_onetimeauth":
                return crypto_onetimeauth(call);
            case "crypto_onetimeauth_verify":
                return crypto_onetimeauth_verify(call);
            case "crypto_onetimeauth_init":
                return crypto_onetimeauth_init(call);
            case "crypto_onetimeauth_update":
                return crypto_onetimeauth_update(call);
            case "crypto_onetimeauth_final":
                return crypto_onetimeauth_final(call);
            case "crypto_onetimeauth_keygen":
                return crypto_onetimeauth_keygen(call);

            case "crypto_pwhash":
                return crypto_pwhash(call);
            case "crypto_pwhash_str":
                return crypto_pwhash_str(call);
            case "crypto_pwhash_str_verify":
                return crypto_pwhash_str_verify(call);
            case "crypto_pwhash_str_needs_rehash":
                return crypto_pwhash_str_needs_rehash(call);

            case "crypto_scalarmult_base":
                return crypto_scalarmult_base(call);
            case "crypto_scalarmult":
                return crypto_scalarmult(call);

            case "crypto_secretbox_easy":
                return crypto_secretbox_easy(call);
            case "crypto_secretbox_open_easy":
                return crypto_secretbox_open_easy(call);
            case "crypto_secretbox_detached":
                return crypto_secretbox_detached(call);
            case "crypto_secretbox_open_detached":
                return crypto_secretbox_open_detached(call);
            case "crypto_secretbox_keygen":
                return crypto_secretbox_keygen(call);

            case "crypto_shorthash":
                return crypto_shorthash(call);
            case "crypto_shorthash_keygen":
                return crypto_shorthash_keygen(call);

            case "crypto_sign_seed_keypair":
                return crypto_sign_seed_keypair(call);
            case "crypto_sign_keypair":
                return crypto_sign_keypair(call);
            case "crypto_sign":
                return crypto_sign(call);
            case "crypto_sign_open":
                return crypto_sign_open(call);
            case "crypto_sign_detached":
                return crypto_sign_detached(call);
            case "crypto_sign_verify_detached":
                return crypto_sign_verify_detached(call);
            case "crypto_sign_init":
                return crypto_sign_init(call);
            case "crypto_sign_update":
                return crypto_sign_update(call);
            case "crypto_sign_final_create":
                return crypto_sign_final_create(call);
            case "crypto_sign_final_verify":
                return crypto_sign_final_verify(call);

            case "randombytes_buf":
                return randombytes_buf(call);
            case "randombytes_buf_deterministic":
                return randombytes_buf_deterministic(call);
            case "randombytes_random":
                return randombytes_random(call);
            case "randombytes_uniform":
                return randombytes_uniform(call);
                
            case "sodium_version_string":
                return sodium_version_string(call);
            default:
                throw new UnsupportedOperationException();
        }
    }

    private static void requireSuccess(int ret) throws Exception {
        if (ret != 0) {
            throw new Exception("result " + ret);
        }
    }

    private Object crypto_aead_chacha20poly1305_encrypt(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] c = new byte[m.length + sodium().crypto_aead_chacha20poly1305_abytes()];
        int[] clen = new int[1];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_chacha20poly1305_encrypt(c, clen, m, m.length, ad, ad.length, new byte[0], npub, k));

        return c;
    }

    private Object crypto_aead_chacha20poly1305_decrypt(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length - sodium().crypto_aead_chacha20poly1305_abytes()];
        int[] mlen = new int[1];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_chacha20poly1305_decrypt(m, mlen, new byte[0], c, c.length, ad, ad.length, npub, k));

        return m;
    }

    private Object crypto_aead_chacha20poly1305_encrypt_detached(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] c = new byte[m.length];
        byte[] mac = new byte[sodium().crypto_aead_chacha20poly1305_abytes()];
        int[] maclen = new int[1];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_chacha20poly1305_encrypt_detached(c, mac, maclen, m, m.length, ad, ad.length, new byte[0], npub, k));
        
        HashMap map = new HashMap();
        map.put("c", c);
        map.put("mac", mac);

        return map;
    }

    private Object crypto_aead_chacha20poly1305_decrypt_detached(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] mac = call.argument("mac");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_chacha20poly1305_decrypt_detached(m, new byte[0], c, c.length, mac, ad, ad.length, npub, k));

        return m;
    }

    private Object crypto_aead_chacha20poly1305_keygen(MethodCall call) throws Exception {
        byte[] k = new byte[sodium().crypto_aead_chacha20poly1305_keybytes()];
        sodium().crypto_aead_chacha20poly1305_keygen(k);

        return k;
    }

    private Object crypto_aead_chacha20poly1305_ietf_encrypt(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] c = new byte[m.length + sodium().crypto_aead_chacha20poly1305_ietf_abytes()];
        int[] clen = new int[1];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, m.length, ad, ad.length, new byte[0], npub, k));

        return c;
    }

    private Object crypto_aead_chacha20poly1305_ietf_decrypt(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length - sodium().crypto_aead_chacha20poly1305_ietf_abytes()];
        int[] mlen = new int[1];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen, new byte[0], c, c.length, ad, ad.length, npub, k));

        return m;
    }

    private Object crypto_aead_chacha20poly1305_ietf_encrypt_detached(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] c = new byte[m.length];
        byte[] mac = new byte[sodium().crypto_aead_chacha20poly1305_ietf_abytes()];
        int[] maclen = new int[1];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, maclen, m, m.length, ad, ad.length, new byte[0], npub, k));
        
        HashMap map = new HashMap();
        map.put("c", c);
        map.put("mac", mac);

        return map;
    }

    private Object crypto_aead_chacha20poly1305_ietf_decrypt_detached(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] mac = call.argument("mac");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, new byte[0], c, c.length, mac, ad, ad.length, npub, k));

        return m;
    }

    private Object crypto_aead_chacha20poly1305_ietf_keygen(MethodCall call) throws Exception {
        byte[] k = new byte[sodium().crypto_aead_chacha20poly1305_ietf_keybytes()];
        sodium().crypto_aead_chacha20poly1305_ietf_keygen(k);

        return k;
    }

    private Object crypto_aead_xchacha20poly1305_ietf_encrypt(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] c = new byte[m.length + sodium().crypto_aead_xchacha20poly1305_ietf_abytes()];
        int[] clen = new int[1];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen, m, m.length, ad, ad.length, new byte[0], npub, k));

        return c;
    }

    private Object crypto_aead_xchacha20poly1305_ietf_decrypt(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length - sodium().crypto_aead_xchacha20poly1305_ietf_abytes()];
        int[] mlen = new int[1];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen, new byte[0], c, c.length, ad, ad.length, npub, k));

        return m;
    }

    private Object crypto_aead_xchacha20poly1305_ietf_encrypt_detached(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] c = new byte[m.length];
        byte[] mac = new byte[sodium().crypto_aead_xchacha20poly1305_ietf_abytes()];
        int[] maclen = new int[1];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, maclen, m, m.length, ad, ad.length, new byte[0], npub, k));
        
        HashMap map = new HashMap();
        map.put("c", c);
        map.put("mac", mac);

        return map;
    }

    private Object crypto_aead_xchacha20poly1305_ietf_decrypt_detached(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] mac = call.argument("mac");
        byte[] ad = call.argument("ad");
        byte[] npub = call.argument("npub");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length];
        if (ad == null) {
            ad = new byte[0];
        }

        requireSuccess(sodium().crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, new byte[0], c, c.length, mac, ad, ad.length, npub, k));

        return m;
    }

    private Object crypto_aead_xchacha20poly1305_ietf_keygen(MethodCall call) throws Exception {
        byte[] k = new byte[sodium().crypto_aead_xchacha20poly1305_ietf_keybytes()];
        sodium().crypto_aead_xchacha20poly1305_ietf_keygen(k);

        return k;
    }

    private Object crypto_auth(MethodCall call) throws Exception {
        byte[] in = call.argument("in");
        byte[] k = call.argument("k");
        byte[] out = new byte[sodium().crypto_auth_bytes()];

        requireSuccess(sodium().crypto_auth(out, in, in.length, k));

        return out;
    }

    private Object crypto_auth_verify(MethodCall call) {
        byte[] h = call.argument("h");
        byte[] in = call.argument("in");
        byte[] k = call.argument("k");

        int ret = sodium().crypto_auth_verify(h, in, in.length, k);

        return ret == 0;
    }

    private Object crypto_auth_keygen(MethodCall call) {
        // FIXME: crypto_auth_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] k = new byte[sodium().crypto_auth_keybytes()];
        sodium().randombytes_buf(k, k.length);

        return k;
    }

    private Object crypto_box_seed_keypair(MethodCall call) throws Exception {
        byte[] seed = call.argument("seed");
        byte[] pk = new byte[sodium().crypto_box_publickeybytes()];
        byte[] sk = new byte[sodium().crypto_box_secretkeybytes()];

        requireSuccess(sodium().crypto_box_seed_keypair(pk, sk, seed));
        HashMap map = new HashMap();
        map.put("pk", pk);
        map.put("sk", sk);

        return map;
    }

    private Object crypto_box_keypair(MethodCall call) throws Exception {
        byte[] pk = new byte[sodium().crypto_box_publickeybytes()];
        byte[] sk = new byte[sodium().crypto_box_secretkeybytes()];

        requireSuccess(sodium().crypto_box_keypair(pk, sk));
        HashMap map = new HashMap();
        map.put("pk", pk);
        map.put("sk", sk);

        return map;
    }

    private Object crypto_box_easy(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] n = call.argument("n");
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");
        byte[] c = new byte[sodium().crypto_box_macbytes() + m.length];

        requireSuccess(sodium().crypto_box_easy(c, m, m.length, n, pk, sk));

        return c;
    }

    private Object crypto_box_open_easy(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] n = call.argument("n");
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");
        byte[] m = new byte[c.length - sodium().crypto_box_macbytes()];

        requireSuccess(sodium().crypto_box_open_easy(m, c, c.length, n, pk, sk));

        return m;
    }

    private Object crypto_box_detached(MethodCall call) throws Exception {
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

        return map;
    }

    private Object crypto_box_open_detached(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] mac = call.argument("mac");
        byte[] n = call.argument("n");
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");

        byte[] m = new byte[c.length];

        requireSuccess(sodium().crypto_box_open_detached(m, c, mac, c.length, n, pk, sk));

        return m;
    }

    private Object crypto_box_beforenm(MethodCall call) throws Exception {
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");

        byte[] k = new byte[sodium().crypto_box_beforenmbytes()];

        requireSuccess(sodium().crypto_box_beforenm(k, pk, sk));

        return k;
    }

    private Object crypto_box_easy_afternm(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");
        byte[] c = new byte[sodium().crypto_box_macbytes() + m.length];

        requireSuccess(sodium().crypto_box_easy_afternm(c, m, m.length, n, k));

        return c;
    }

    private Object crypto_box_open_easy_afternm(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length - sodium().crypto_box_macbytes()];

        requireSuccess(sodium().crypto_box_open_easy_afternm(m, c, c.length, n, k));

        return m;
    }

    private Object crypto_box_detached_afternm(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");

        byte[] c = new byte[m.length];
        byte[] mac = new byte[sodium().crypto_box_macbytes()];

        requireSuccess(sodium().crypto_box_detached_afternm(c, mac, m, m.length, n, k));

        HashMap map = new HashMap();
        map.put("c", c);
        map.put("mac", mac);

        return map;
    }

    private Object crypto_box_open_detached_afternm(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] mac = call.argument("mac");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");

        byte[] m = new byte[c.length];

        requireSuccess(sodium().crypto_box_open_detached_afternm(m, c, mac, c.length, n, k));

        return m;
    }

    private Object crypto_box_seal(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] pk = call.argument("pk");

        byte[] c = new byte[sodium().crypto_box_sealbytes() + m.length];

        requireSuccess(sodium().crypto_box_seal(c, m, m.length, pk));

        return c;
    }

    private Object crypto_box_seal_open(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");

        byte[] m = new byte[c.length - sodium().crypto_box_sealbytes()];

        requireSuccess(sodium().crypto_box_seal_open(m, c, c.length, pk, sk));

        return m;
    }

    private Object crypto_box_curve25519xchacha20poly1305_seed_keypair(MethodCall call) throws Exception {
        byte[] seed = call.argument("seed");
        byte[] pk = new byte[sodium().crypto_box_curve25519xchacha20poly1305_publickeybytes()];
        byte[] sk = new byte[sodium().crypto_box_curve25519xchacha20poly1305_secretkeybytes()];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_seed_keypair(pk, sk, seed));
        HashMap map = new HashMap();
        map.put("pk", pk);
        map.put("sk", sk);

        return map;
    }

    private Object crypto_box_curve25519xchacha20poly1305_keypair(MethodCall call) throws Exception {
        byte[] pk = new byte[sodium().crypto_box_curve25519xchacha20poly1305_publickeybytes()];
        byte[] sk = new byte[sodium().crypto_box_curve25519xchacha20poly1305_secretkeybytes()];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_keypair(pk, sk));
        HashMap map = new HashMap();
        map.put("pk", pk);
        map.put("sk", sk);

        return map;
    }

    private Object crypto_box_curve25519xchacha20poly1305_easy(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] n = call.argument("n");
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");
        byte[] c = new byte[sodium().crypto_box_curve25519xchacha20poly1305_macbytes() + m.length];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_easy(c, m, m.length, n, pk, sk));

        return c;
    }

    private Object crypto_box_curve25519xchacha20poly1305_open_easy(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] n = call.argument("n");
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");
        byte[] m = new byte[c.length - sodium().crypto_box_curve25519xchacha20poly1305_macbytes()];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_open_easy(m, c, c.length, n, pk, sk));

        return m;
    }

    private Object crypto_box_curve25519xchacha20poly1305_detached(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] n = call.argument("n");
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");

        byte[] c = new byte[m.length];
        byte[] mac = new byte[sodium().crypto_box_curve25519xchacha20poly1305_macbytes()];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_detached(c, mac, m, m.length, n, pk, sk));

        HashMap map = new HashMap();
        map.put("c", c);
        map.put("mac", mac);

        return map;
    }

    private Object crypto_box_curve25519xchacha20poly1305_open_detached(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] mac = call.argument("mac");
        byte[] n = call.argument("n");
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");

        byte[] m = new byte[c.length];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_open_detached(m, c, mac, c.length, n, pk, sk));

        return m;
    }

    private Object crypto_box_curve25519xchacha20poly1305_beforenm(MethodCall call) throws Exception {
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");

        byte[] k = new byte[sodium().crypto_box_curve25519xchacha20poly1305_beforenmbytes()];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_beforenm(k, pk, sk));

        return k;
    }

    private Object crypto_box_curve25519xchacha20poly1305_easy_afternm(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");
        byte[] c = new byte[sodium().crypto_box_curve25519xchacha20poly1305_macbytes() + m.length];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_easy_afternm(c, m, m.length, n, k));

        return c;
    }

    private Object crypto_box_curve25519xchacha20poly1305_open_easy_afternm(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length - sodium().crypto_box_curve25519xchacha20poly1305_macbytes()];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m, c, c.length, n, k));

        return m;
    }

    private Object crypto_box_curve25519xchacha20poly1305_detached_afternm(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");

        byte[] c = new byte[m.length];
        byte[] mac = new byte[sodium().crypto_box_curve25519xchacha20poly1305_macbytes()];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_detached_afternm(c, mac, m, m.length, n, k));

        HashMap map = new HashMap();
        map.put("c", c);
        map.put("mac", mac);

        return map;
    }

    private Object crypto_box_curve25519xchacha20poly1305_open_detached_afternm(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] mac = call.argument("mac");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");

        byte[] m = new byte[c.length];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m, c, mac, c.length, n, k));

        return m;
    }

    private Object crypto_box_curve25519xchacha20poly1305_seal(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] pk = call.argument("pk");

        byte[] c = new byte[sodium().crypto_box_curve25519xchacha20poly1305_sealbytes() + m.length];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_seal(c, m, m.length, pk));

        return c;
    }

    private Object crypto_box_curve25519xchacha20poly1305_seal_open(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] pk = call.argument("pk");
        byte[] sk = call.argument("sk");

        byte[] m = new byte[c.length - sodium().crypto_box_curve25519xchacha20poly1305_sealbytes()];

        requireSuccess(sodium().crypto_box_curve25519xchacha20poly1305_seal_open(m, c, c.length, pk, sk));

        return m;
    }

    private Object crypto_generichash(MethodCall call) throws Exception {
        int outlen = call.argument("outlen");
        byte[] in = call.argument("in");
        byte[] key = call.argument("key");
        if (key == null) {
            key = new byte[0];
        }
        byte[] out = new byte[outlen];

        requireSuccess(sodium().crypto_generichash(out, outlen, in, in.length, key, key.length));

        return out;
    }

    private Object crypto_generichash_init(MethodCall call) throws Exception {
        byte[] key = call.argument("key");
        int outlen = call.argument("outlen");

        if (key == null) {
            key = new byte[0];
        }
        byte[] state = new byte[sodium().crypto_generichash_statebytes()];

        requireSuccess(sodium().crypto_generichash_init(state, key, key.length, outlen));

        return state;
    }

    private Object crypto_generichash_update(MethodCall call) throws Exception {
        byte[] state = call.argument("state");
        byte[] in = call.argument("in");

        requireSuccess(sodium().crypto_generichash_update(state, in, in.length));

        return state;
    }

    private Object crypto_generichash_final(MethodCall call) throws Exception {
        byte[] state = call.argument("state");
        int outlen = call.argument("outlen");

        byte[] out = new byte[outlen];

        requireSuccess(sodium().crypto_generichash_final(state, out, outlen));

        return out;
    }

    private Object crypto_generichash_keygen(MethodCall call) {
        // FIXME: crypto_generichash_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] k = new byte[sodium().crypto_generichash_keybytes()];
        sodium().randombytes_buf(k, k.length);

        return k;
    }

    private Object crypto_kdf_keygen(MethodCall call) {
        // FIXME: crypto_kdf_keygen not implemented in libsodium-jni
        throw new UnsupportedOperationException();
    }

    private Object crypto_kdf_derive_from_key(MethodCall call) {
        // FIXME: crypto_kdf_derive_from_key not implemented in libsodium-jni
        throw new UnsupportedOperationException();
    }

    private Object crypto_kx_keypair(MethodCall call) throws Exception {
        byte[] pk = new byte[32];
        byte[] sk = new byte[32];

        requireSuccess(sodium().crypto_kx_keypair(pk, sk));
        HashMap map = new HashMap();
        map.put("pk", pk);
        map.put("sk", sk);

        return map;
    }

    private Object crypto_kx_seed_keypair(MethodCall call) throws Exception {
        byte[] seed = call.argument("seed");

        byte[] pk = new byte[32];
        byte[] sk = new byte[32];

        requireSuccess(sodium().crypto_kx_seed_keypair(pk, sk, seed));
        HashMap map = new HashMap();
        map.put("pk", pk);
        map.put("sk", sk);

        return map;
    }

    private Object crypto_kx_client_session_keys(MethodCall call) throws Exception {
        byte[] client_pk = call.argument("client_pk");
        byte[] client_sk = call.argument("client_sk");
        byte[] server_pk = call.argument("server_pk");

        byte[] rx = new byte[32];
        byte[] tx = new byte[32];

        requireSuccess(sodium().crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk));
        HashMap map = new HashMap();
        map.put("rx", rx);
        map.put("tx", tx);

        return map;
    }

    private Object crypto_kx_server_session_keys(MethodCall call) throws Exception {
        byte[] server_pk = call.argument("server_pk");
        byte[] server_sk = call.argument("server_sk");
        byte[] client_pk = call.argument("client_pk");

        byte[] rx = new byte[32];
        byte[] tx = new byte[32];

        requireSuccess(sodium().crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk));
        HashMap map = new HashMap();
        map.put("rx", rx);
        map.put("tx", tx);

        return map;
    }

    private Object crypto_onetimeauth(MethodCall call) throws Exception {
        byte[] in = call.argument("in");
        byte[] k = call.argument("k");

        byte[] out = new byte[sodium().crypto_onetimeauth_bytes()];
        requireSuccess(sodium().crypto_onetimeauth(out, in, in.length, k));

        return out;
    }

    private Object crypto_onetimeauth_verify(MethodCall call) {
        byte[] h = call.argument("h");
        byte[] in = call.argument("in");
        byte[] k = call.argument("k");

        int ret = sodium().crypto_onetimeauth_verify(h, in, in.length, k);

        return ret == 0;
    }

    private Object crypto_onetimeauth_init(MethodCall call) throws Exception {
        byte[] key = call.argument("key");
        byte[] state = new byte[sodium().crypto_onetimeauth_statebytes()];

        requireSuccess(sodium().crypto_onetimeauth_init(state, key));

        return state;
    }

    private Object crypto_onetimeauth_update(MethodCall call) throws Exception {
        byte[] state = call.argument("state");
        byte[] in = call.argument("in");

        requireSuccess(sodium().crypto_onetimeauth_update(state, in, in.length));

        return state;
    }

    private Object crypto_onetimeauth_final(MethodCall call) throws Exception {
        byte[] state = call.argument("state");
        byte[] out = new byte[sodium().crypto_onetimeauth_bytes()];

        requireSuccess(sodium().crypto_onetimeauth_final(state, out));

        return out;
    }

    private Object crypto_onetimeauth_keygen(MethodCall call) {
        // FIXME: crypto_onetimeauth_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] k = new byte[sodium().crypto_onetimeauth_keybytes()];
        sodium().randombytes_buf(k, k.length);

        return k;
    }

    private Object crypto_pwhash(MethodCall call) throws Exception {
        int outlen = call.argument("outlen");
        byte[] passwd = call.argument("passwd");
        byte[] salt = call.argument("salt");
        int opslimit = call.argument("opslimit");
        int memlimit = call.argument("memlimit");
        int alg = call.argument("alg");

        byte[] out = new byte[outlen];

        requireSuccess(sodium().crypto_pwhash(out, outlen, passwd, passwd.length, salt, opslimit, memlimit, alg));

        return out;
    }

    private Object crypto_pwhash_str(MethodCall call) throws Exception {
        byte[] passwd = call.argument("passwd");
        int opslimit = call.argument("opslimit");
        int memlimit = call.argument("memlimit");

        byte[] out = new byte[sodium().crypto_pwhash_strbytes()];

        requireSuccess(sodium().crypto_pwhash_str(out, passwd, passwd.length, opslimit, memlimit));

        return out;
    }

    private Object crypto_pwhash_str_verify(MethodCall call) {
        byte[] str = call.argument("str");
        byte[] passwd = call.argument("passwd");

        int ret = sodium().crypto_pwhash_str_verify(str, passwd, passwd.length);

        return ret == 0;
    }

    private Object crypto_pwhash_str_needs_rehash(MethodCall call) throws Exception {
        // FIXME: crypto_pwhash_str_needs_rehash not implemented in libsodium-jni
        throw new UnsupportedOperationException();
    }

    private Object crypto_scalarmult_base(MethodCall call) throws Exception {
        byte[] n = call.argument("n");
        byte[] q = new byte[sodium().crypto_scalarmult_bytes()];

        requireSuccess(sodium().crypto_scalarmult_base(q, n));

        return q;
    }

    private Object crypto_scalarmult(MethodCall call) throws Exception {
        byte[] n = call.argument("n");
        byte[] p = call.argument("p");
        byte[] q = new byte[sodium().crypto_scalarmult_bytes()];

        requireSuccess(sodium().crypto_scalarmult(q, n, p));

        return q;
    }

    private Object crypto_secretbox_easy(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");
        byte[] c = new byte[sodium().crypto_secretbox_macbytes() + m.length];

        requireSuccess(sodium().crypto_secretbox_easy(c, m, m.length, n, k));

        return c;
    }

    private Object crypto_secretbox_open_easy(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length - sodium().crypto_secretbox_macbytes()];

        requireSuccess(sodium().crypto_secretbox_open_easy(m, c, c.length, n, k));

        return m;
    }

    private Object crypto_secretbox_detached(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");
        byte[] c = new byte[m.length];
        byte[] mac = new byte[sodium().crypto_secretbox_macbytes()];

        requireSuccess(sodium().crypto_secretbox_detached(c, mac, m, m.length, n, k));

        HashMap map = new HashMap();
        map.put("c", c);
        map.put("mac", mac);

        return map;
    }

    private Object crypto_secretbox_open_detached(MethodCall call) throws Exception {
        byte[] c = call.argument("c");
        byte[] mac = call.argument("mac");
        byte[] n = call.argument("n");
        byte[] k = call.argument("k");
        byte[] m = new byte[c.length];

        requireSuccess(sodium().crypto_secretbox_open_detached(m, c, mac, c.length, n, k));

        return m;
    }

    private Object crypto_secretbox_keygen(MethodCall call) {
        // FIXME: crypto_secretbox_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] k = new byte[sodium().crypto_secretbox_keybytes()];
        sodium().randombytes_buf(k, k.length);

        return k;
    }

    private Object crypto_shorthash(MethodCall call) throws Exception {
        byte[] in = call.argument("in");
        byte[] k = call.argument("k");

        byte[] out = new byte[sodium().crypto_shorthash_bytes()];

        requireSuccess(sodium().crypto_shorthash(out, in, in.length, k));

        return out;
    }

    private Object crypto_shorthash_keygen(MethodCall call) {
        // FIXME: crypto_shorthash_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] k = new byte[sodium().crypto_shorthash_keybytes()];
        sodium().randombytes_buf(k, k.length);

        return k;
    }

    private Object crypto_sign_seed_keypair(MethodCall call) throws Exception {
        byte[] seed = call.argument("seed");
        byte[] pk = new byte[sodium().crypto_sign_publickeybytes()];
        byte[] sk = new byte[sodium().crypto_sign_secretkeybytes()];

        requireSuccess(sodium().crypto_sign_seed_keypair(pk, sk, seed));
        HashMap map = new HashMap();
        map.put("pk", pk);
        map.put("sk", sk);

        return map;
    }

    private Object crypto_sign_keypair(MethodCall call) throws Exception {
        byte[] pk = new byte[sodium().crypto_sign_publickeybytes()];
        byte[] sk = new byte[sodium().crypto_sign_secretkeybytes()];

        requireSuccess(sodium().crypto_sign_keypair(pk, sk));
        HashMap map = new HashMap();
        map.put("pk", pk);
        map.put("sk", sk);

        return map;
    }

    private Object crypto_sign(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] sk = call.argument("sk");
        byte[] sm = new byte[m.length + sodium().crypto_sign_bytes()];
        int[] smlen = new int[1];

        requireSuccess(sodium().crypto_sign(sm, smlen, m, m.length, sk));

        return sm;
    }

    private Object crypto_sign_open(MethodCall call) throws Exception {
        byte[] sm = call.argument("sm");
        byte[] pk = call.argument("pk");
        byte[] m = new byte[sm.length - sodium().crypto_sign_bytes()];
        int[] mlen = new int[1];
        requireSuccess(sodium().crypto_sign_open(m, mlen, sm, sm.length, pk));

        return m;
    }

    private Object crypto_sign_detached(MethodCall call) throws Exception {
        byte[] m = call.argument("m");
        byte[] sk = call.argument("sk");
        byte[] sig = new byte[sodium().crypto_sign_bytes()];
        int[] siglen = new int[1];

        requireSuccess(sodium().crypto_sign_detached(sig, siglen, m, m.length, sk));

        return sig;
    }

    private Object crypto_sign_verify_detached(MethodCall call) {
        byte[] sig = call.argument("sig");
        byte[] m = call.argument("m");
        byte[] pk = call.argument("pk");

        int ret = sodium().crypto_sign_verify_detached(sig, m, m.length, pk);
        return ret == 0;
    }

    private Object crypto_sign_init(MethodCall call) throws Exception {
        // byte[] state = new byte[sodium().crypto_sign_statebytes()];
        // requireSuccess(sodium().crypto_sign_init(state));
        // result.success(state);

        // FIXME: crypto_sign_init not implemented in libsodium-jni
        throw new UnsupportedOperationException();
    }

    private Object crypto_sign_update(MethodCall call) throws Exception {
        // byte[] state = call.argument("state");
        // byte[] m = call.argument("m");
        // requireSuccess(sodium().crypto_sign_update(state, m, m.length));
        // result.success(state);

        // FIXME: crypto_sign_update not implemented in libsodium-jni
        throw new UnsupportedOperationException();
    }

    private Object crypto_sign_final_create(MethodCall call) throws Exception {
        // byte[] state = call.argument("state");
        // byte[] sk = call.argument("sk");
        // byte[] sig = new byte[sodium().crypto_sign_bytes()];
        // int[] siglen = new int[1];

        // requireSuccess(sodium().crypto_sign_final_create(state, sig, siglen, sk));
        // result.success(sig);

        // FIXME: crypto_sign_final_create not implemented in libsodium-jni
        throw new UnsupportedOperationException();
    }

    private Object crypto_sign_final_verify(MethodCall call) {
        // byte[] state = call.argument("state");
        // byte[] sig = call.argument("sig");
        // byte[] pk = call.argument("pk");

        // int ret = sodium().crypto_sign_final_verify(state, sig, pk);
        // result.success(ret == 0);

        // FIXME: crypto_sign_final_verify not implemented in libsodium-jni
        throw new UnsupportedOperationException();
    }

    private Object randombytes_buf(MethodCall call) {
        int size = call.argument("size");
        byte[] buf = new byte[size];
        sodium().randombytes_buf(buf, size);
        return buf;
    }

    private Object randombytes_buf_deterministic(MethodCall call) {
        // FIXME: randombytes_buf_deterministic not implemented in libsodium-jni
        throw new UnsupportedOperationException();
    }

    private Object randombytes_random(MethodCall call) {
        int rnd = sodium().randombytes_random();
        // convert result to unsigned long
        return rnd & 0xFFFFFFFFL;
    }

    private Object randombytes_uniform(MethodCall call) {
        int upper_bound = call.argument("upper_bound");
        return sodium().randombytes_uniform(upper_bound);
    }

    private Object sodium_version_string(MethodCall call) {
        // FIXME: sodium_version_string throws in libsodium-jni
        // for now version is hardcoded
        return "1.0.16";
    }
}