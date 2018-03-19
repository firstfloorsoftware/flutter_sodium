import Flutter
import UIKit
    
public class SwiftFlutterSodiumPlugin: NSObject, FlutterPlugin {
  private static var sodiumInitResult : Int32 = -1

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_sodium", binaryMessenger: registrar.messenger())
    let instance = SwiftFlutterSodiumPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)

    sodiumInitResult = sodium_init()
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    if (SwiftFlutterSodiumPlugin.sodiumInitResult < 0) {
      result(FlutterError.init(code: "Failure", message: "Sodium failed to initialize", details: nil))
      return
    }

    switch call.method {
      case "crypto_auth": result(crypto_auth(call:call))
      case "crypto_auth_verify": result(crypto_auth_verify(call:call))
      case "crypto_auth_keygen": result(crypto_auth_keygen(call:call))

      case "crypto_box_seed_keypair": result(crypto_box_seed_keypair(call: call))
      case "crypto_box_keypair": result(crypto_box_keypair(call: call))
      case "crypto_box_easy": result(crypto_box_easy(call:call))
      case "crypto_box_open_easy": result(crypto_box_open_easy(call:call))
      case "crypto_box_detached": result(crypto_box_detached(call:call))
      case "crypto_box_open_detached": result(crypto_box_open_detached(call:call))
      case "crypto_box_beforenm": result(crypto_box_beforenm(call:call))
      case "crypto_box_easy_afternm": result(crypto_box_easy_afternm(call:call))
      case "crypto_box_open_easy_afternm": result(crypto_box_open_easy_afternm(call:call))
      case "crypto_box_detached_afternm": result(crypto_box_detached_afternm(call:call))
      case "crypto_box_open_detached_afternm": result(crypto_box_open_detached_afternm(call:call))

      case "crypto_box_seal": result(crypto_box_seal(call: call))
      case "crypto_box_seal_open": result(crypto_box_seal_open(call: call))

      case "crypto_generichash": result(crypto_generichash(call: call))
      case "crypto_generichash_init": result(crypto_generichash_init(call: call))
      case "crypto_generichash_update": result(crypto_generichash_update(call: call))
      case "crypto_generichash_final": result(crypto_generichash_final(call: call))
      case "crypto_generichash_keygen": result(crypto_generichash_keygen(call: call))

      case "crypto_kdf_keygen": result(crypto_kdf_keygen(call: call))
      case "crypto_kdf_derive_from_key": result(crypto_kdf_derive_from_key(call: call))

      case "crypto_kx_keypair": result(crypto_kx_keypair(call: call))
      case "crypto_kx_seed_keypair": result(crypto_kx_seed_keypair(call: call))
      case "crypto_kx_client_session_keys": result(crypto_kx_client_session_keys(call: call))
      case "crypto_kx_server_session_keys": result(crypto_kx_server_session_keys(call: call))

      case "crypto_onetimeauth": result(crypto_onetimeauth(call: call))
      case "crypto_onetimeauth_verify": result(crypto_onetimeauth_verify(call: call))
      case "crypto_onetimeauth_init": result(crypto_onetimeauth_init(call: call))
      case "crypto_onetimeauth_update": result(crypto_onetimeauth_update(call: call))
      case "crypto_onetimeauth_final": result(crypto_onetimeauth_final(call: call))
      case "crypto_onetimeauth_keygen": result(crypto_onetimeauth_keygen(call: call))

      case "crypto_pwhash": result(crypto_pwhash(call: call))
      case "crypto_pwhash_str": result(crypto_pwhash_str(call: call))
      case "crypto_pwhash_str_verify": result(crypto_pwhash_str_verify(call: call))
      case "crypto_pwhash_str_needs_rehash": result(crypto_pwhash_str_needs_rehash(call: call))

      case "crypto_scalarmult_base": result(crypto_scalarmult_base(call: call))
      case "crypto_scalarmult": result(crypto_scalarmult(call: call))

      case "crypto_secretbox_easy": result(crypto_secretbox_easy(call: call))
      case "crypto_secretbox_open_easy": result(crypto_secretbox_open_easy(call: call))
      case "crypto_secretbox_detached": result(crypto_secretbox_detached(call: call))
      case "crypto_secretbox_open_detached": result(crypto_secretbox_open_detached(call: call))
      case "crypto_secretbox_keygen": result(crypto_secretbox_keygen(call: call))

      case "crypto_shorthash": result(crypto_shorthash(call: call))
      case "crypto_shorthash_keygen": result(crypto_shorthash_keygen(call: call))

      case "crypto_sign_seed_keypair": result(crypto_sign_seed_keypair(call: call))
      case "crypto_sign_keypair": result(crypto_sign_keypair(call: call))
      case "crypto_sign": result(crypto_sign(call: call))
      case "crypto_sign_open": result(crypto_sign_open(call: call))
      case "crypto_sign_detached": result(crypto_sign_detached(call: call))
      case "crypto_sign_verify_detached": result(crypto_sign_verify_detached(call: call))
      case "crypto_sign_init": result(crypto_sign_init(call: call))
      case "crypto_sign_update": result(crypto_sign_update(call: call))
      case "crypto_sign_final_create": result(crypto_sign_final_create(call: call))
      case "crypto_sign_final_verify": result(crypto_sign_final_verify(call: call))

      case "randombytes_buf": result(randombytes_buf(call: call))
      case "randombytes_buf_deterministic": result(randombytes_buf_deterministic(call: call))
      case "randombytes_random": result(randombytes_random(call: call))
      case "randombytes_uniform": result(randombytes_uniform(call: call))
      case "randombytes_stir": result(randombytes_stir(call: call))
      case "randombytes_close": result(randombytes_close(call: call))

      case "sodium_version_string": result(sodium_version_string(call: call))
      
      default: result(FlutterMethodNotImplemented)
    }
  }

  private func error(ret: Int32, function: String = #function) -> FlutterError?
  {
    if (ret != 0) {
      return FlutterError.init(code: "Failure", message: "\(function) returns \(ret)", details: nil)
    }
    return nil
  }

  private func crypto_auth(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let i = (args["in"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var out = Data(count: flutter_sodium.crypto_auth_bytes())

    let ret = out.withUnsafeMutableBytes { outPtr in
      i.withUnsafeBytes { iPtr in 
        k.withUnsafeBytes { kPtr in
          flutter_sodium.crypto_auth(outPtr, iPtr, CUnsignedLongLong(i.count), kPtr)
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: out)
  }

  private func crypto_auth_verify(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let h = (args["h"] as! FlutterStandardTypedData).data
    let i = (args["in"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data
    
    let ret = h.withUnsafeBytes { hPtr in
      i.withUnsafeBytes { iPtr in
        k.withUnsafeBytes { kPtr in 
          flutter_sodium.crypto_auth_verify(hPtr, iPtr, CUnsignedLongLong(i.count), kPtr)
        }
      }
    }
    return ret == 0
  }

  private func crypto_auth_keygen(call: FlutterMethodCall) -> Any
  {
    var k = Data(count: flutter_sodium.crypto_auth_keybytes())
    k.withUnsafeMutableBytes { kPtr in
      flutter_sodium.crypto_auth_keygen(kPtr)
    }
    return FlutterStandardTypedData.init(bytes: k)
  }

  private func crypto_box_seed_keypair(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let seed = (args["seed"] as! FlutterStandardTypedData).data
    
    var pk = Data(count: flutter_sodium.crypto_box_publickeybytes())
    var sk = Data(count: flutter_sodium.crypto_box_secretkeybytes())
    let ret = pk.withUnsafeMutableBytes { pkPtr in
      sk.withUnsafeMutableBytes { skPtr in
        seed.withUnsafeBytes { seedPtr in
          flutter_sodium.crypto_box_seed_keypair(pkPtr, skPtr, seedPtr)
        }
      }
    }
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: pk),
      "sk": FlutterStandardTypedData.init(bytes: sk)
    ]
  }
  
  private func crypto_box_keypair(call: FlutterMethodCall) -> Any
  {
    var pk = Data(count: flutter_sodium.crypto_box_publickeybytes())
    var sk = Data(count: flutter_sodium.crypto_box_secretkeybytes())
    let ret = pk.withUnsafeMutableBytes { pkPtr in
      sk.withUnsafeMutableBytes { skPtr in
        flutter_sodium.crypto_box_keypair(pkPtr, skPtr)
      }
    }
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: pk),
      "sk": FlutterStandardTypedData.init(bytes: sk)
    ]
  }

  private func crypto_box_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let pk = (args["pk"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).data

    var c = Data(count: flutter_sodium.crypto_box_macbytes() + m.count)

    let ret = c.withUnsafeMutableBytes { cPtr in
      m.withUnsafeBytes { mPtr in
        n.withUnsafeBytes { nPtr in
          pk.withUnsafeBytes { pkPtr in
            sk.withUnsafeBytes { skPtr in
              flutter_sodium.crypto_box_easy(cPtr, mPtr, CUnsignedLongLong(m.count), nPtr, pkPtr, skPtr)
            }
          }
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: c)
  }

  private func crypto_box_open_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let pk = (args["pk"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).data

    var m = Data(count: c.count - flutter_sodium.crypto_box_macbytes())

    let ret = m.withUnsafeMutableBytes { mPtr in
      c.withUnsafeBytes { cPtr in
        n.withUnsafeBytes { nPtr in
          pk.withUnsafeBytes { pkPtr in
            sk.withUnsafeBytes { skPtr in
              flutter_sodium.crypto_box_open_easy(mPtr, cPtr, CUnsignedLongLong(c.count), nPtr, pkPtr, skPtr)
            }
          }
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: m)
  }

  private func crypto_box_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let pk = (args["pk"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).data

    var c = Data(count: m.count)
    var mac = Data(count: flutter_sodium.crypto_box_macbytes())

    let ret = c.withUnsafeMutableBytes { cPtr in
      mac.withUnsafeMutableBytes { macPtr in
        m.withUnsafeBytes { mPtr in
          n.withUnsafeBytes { nPtr in
            pk.withUnsafeBytes { pkPtr in
              sk.withUnsafeBytes { skPtr in
                flutter_sodium.crypto_box_detached(cPtr, macPtr, mPtr, CUnsignedLongLong(m.count), nPtr, pkPtr, skPtr)
              }
            }
          }
        }
      }
    }
    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: c),
      "mac": FlutterStandardTypedData.init(bytes: mac)
    ]
  }

  private func crypto_box_open_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).data
    let mac = (args["mac"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let pk = (args["pk"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).data

    var m = Data(count: c.count)

    let ret = m.withUnsafeMutableBytes { mPtr in
      mac.withUnsafeBytes { macPtr in
        c.withUnsafeBytes { cPtr in
          n.withUnsafeBytes { nPtr in
            pk.withUnsafeBytes { pkPtr in
              sk.withUnsafeBytes { skPtr in
                flutter_sodium.crypto_box_open_detached(mPtr, cPtr, macPtr, CUnsignedLongLong(c.count), nPtr, pkPtr, skPtr)
              }
            }
          }
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: m)
  }

  private func crypto_box_beforenm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let pk = (args["pk"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).data

    var k = Data(count: flutter_sodium.crypto_box_beforenmbytes())
    let ret = k.withUnsafeMutableBytes { kPtr in
      pk.withUnsafeBytes { pkPtr in
        sk.withUnsafeBytes { skPtr in
          flutter_sodium.crypto_box_beforenm(kPtr, pkPtr, skPtr)
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: k)
  }

  private func crypto_box_easy_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var c = Data(count: flutter_sodium.crypto_box_macbytes() + m.count)

    let ret = c.withUnsafeMutableBytes { cPtr in
      m.withUnsafeBytes { mPtr in
        n.withUnsafeBytes { nPtr in
          k.withUnsafeBytes { kPtr in
            flutter_sodium.crypto_box_easy_afternm(cPtr, mPtr, CUnsignedLongLong(m.count), nPtr, kPtr)
          }
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: c)
  }

  private func crypto_box_open_easy_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var m = Data(count: c.count - flutter_sodium.crypto_box_macbytes())

    let ret = m.withUnsafeMutableBytes { mPtr in
      c.withUnsafeBytes { cPtr in
        n.withUnsafeBytes { nPtr in
          k.withUnsafeBytes { kPtr in
            flutter_sodium.crypto_box_open_easy_afternm(mPtr, cPtr, CUnsignedLongLong(c.count), nPtr, kPtr)
          }
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: m)
  }

  private func crypto_box_detached_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var c = Data(count: m.count)
    var mac = Data(count: flutter_sodium.crypto_box_macbytes())

    let ret = c.withUnsafeMutableBytes { cPtr in
      mac.withUnsafeMutableBytes { macPtr in
        m.withUnsafeBytes { mPtr in
          n.withUnsafeBytes { nPtr in
            k.withUnsafeBytes { kPtr in
              flutter_sodium.crypto_box_detached_afternm(cPtr, macPtr, mPtr, CUnsignedLongLong(m.count), nPtr, kPtr)
            }
          }
        }
      }
    }
    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: c),
      "mac": FlutterStandardTypedData.init(bytes: mac)
    ]
  }
  
  private func crypto_box_open_detached_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).data
    let mac = (args["mac"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var m = Data(count: c.count)

    let ret = m.withUnsafeMutableBytes { mPtr in
      mac.withUnsafeBytes { macPtr in
        c.withUnsafeBytes { cPtr in
          n.withUnsafeBytes { nPtr in
            k.withUnsafeBytes { kPtr in
              flutter_sodium.crypto_box_open_detached_afternm(mPtr, cPtr, macPtr, CUnsignedLongLong(c.count), nPtr, kPtr)
            }
          }
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: m)
  }
  
  private func crypto_box_seal(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).data
    let pk = (args["pk"] as! FlutterStandardTypedData).data
    
    var c = Data(count: m.count + flutter_sodium.crypto_box_sealbytes())
    
    let ret = c.withUnsafeMutableBytes { cPtr in
      m.withUnsafeBytes { mPtr in
        pk.withUnsafeBytes { pkPtr in
          flutter_sodium.crypto_box_seal(cPtr, mPtr, CUnsignedLongLong(m.count), pkPtr)
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: c)
  }
  
  private func crypto_box_seal_open(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).data
    let pk = (args["pk"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).data
    
    var m = Data(count: c.count - flutter_sodium.crypto_box_sealbytes())
    
    let ret = m.withUnsafeMutableBytes { mPtr in
      c.withUnsafeBytes { cPtr in
        pk.withUnsafeBytes { pkPtr in
          sk.withUnsafeBytes { skPtr in
            flutter_sodium.crypto_box_seal_open(mPtr, cPtr, CUnsignedLongLong(c.count), pkPtr, skPtr)
          }
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: m)
  }

  private func crypto_generichash(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let outlen = args["outlen"] as! Int
    let i = (args["in"] as! FlutterStandardTypedData).data
    let key: Data? = (args["key"] as? FlutterStandardTypedData)?.data
    var out = Data(count: outlen)
    var ret: Int32 = -1
    
    if let key = key {
      ret = out.withUnsafeMutableBytes { outPtr in
        i.withUnsafeBytes { inPtr in
          key.withUnsafeBytes { keyPtr in
            flutter_sodium.crypto_generichash(outPtr, outlen, inPtr, CUnsignedLongLong(i.count), keyPtr, key.count)
          }
        }
      }
    }
    else {
      ret = out.withUnsafeMutableBytes { outPtr in
        i.withUnsafeBytes { iPtr in
          flutter_sodium.crypto_generichash(outPtr, outlen, iPtr, CUnsignedLongLong(i.count), nil, 0)
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: out)
  }
    
  private func crypto_generichash_init(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let key: Data? = (args["key"] as? FlutterStandardTypedData)?.data
    let outlen = args["outlen"] as! Int
    var ret: Int32 = -1
    var state = Data(count: crypto_generichash_statebytes())
    
    if let key = key {
      ret = state.withUnsafeMutableBytes { statePtr in 
        key.withUnsafeBytes { keyPtr in 
          flutter_sodium.crypto_generichash_init(statePtr, keyPtr, key.count, outlen)
        }
      }
    }
    else {
      ret = state.withUnsafeMutableBytes { statePtr in 
        flutter_sodium.crypto_generichash_init(statePtr, nil, 0, outlen)
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: state)
  }
  
  private func crypto_generichash_update(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    let i = (args["in"] as! FlutterStandardTypedData).data

    let ret = state.withUnsafeMutableBytes { statePtr in 
      i.withUnsafeBytes { iPtr in 
        flutter_sodium.crypto_generichash_update(statePtr, iPtr, CUnsignedLongLong(i.count))
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: state)
  }
  
  private func crypto_generichash_final(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    let outlen = args["outlen"] as! Int

    var out = Data(count: outlen)

    let ret = state.withUnsafeMutableBytes { statePtr in 
      out.withUnsafeMutableBytes { outPtr in 
        flutter_sodium.crypto_generichash_final(statePtr, outPtr, outlen)
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: out)
  }
  
  private func crypto_generichash_keygen(call: FlutterMethodCall) -> Any
  {
    var k = Data(count: crypto_generichash_keybytes())
    k.withUnsafeMutableBytes { kPtr in
        flutter_sodium.crypto_generichash_keygen(kPtr)
    }
    return FlutterStandardTypedData.init(bytes: k)
  }

  private func crypto_kdf_keygen(call: FlutterMethodCall) -> Any
  {
    var k = Data(count: crypto_kdf_keybytes())
    k.withUnsafeMutableBytes { kPtr in
        flutter_sodium.crypto_kdf_keygen(kPtr)
    }
    return FlutterStandardTypedData.init(bytes: k)
  }

  private func crypto_kdf_derive_from_key(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let subkey_len = args["subkey_len"] as! Int
    let subkey_id = args["subkey_id"] as! UInt64
    let ctx = (args["ctx"] as! FlutterStandardTypedData).data
    let key = (args["key"] as! FlutterStandardTypedData).data

    var subkey = Data(count: subkey_len)
    let ret = subkey.withUnsafeMutableBytes { subkeyPtr in 
      ctx.withUnsafeBytes { ctxPtr in 
        key.withUnsafeBytes { keyPtr in 
          flutter_sodium.crypto_kdf_derive_from_key(subkeyPtr, size_t(subkey_len), subkey_id, ctxPtr, keyPtr)
        }
      }
    }

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: subkey)
  }

  private func crypto_kx_keypair(call: FlutterMethodCall) -> Any
  {
    var pk = Data(count: flutter_sodium.crypto_kx_publickeybytes())
    var sk = Data(count: flutter_sodium.crypto_kx_secretkeybytes())
    let ret = pk.withUnsafeMutableBytes { pkPtr in
      sk.withUnsafeMutableBytes { skPtr in
        flutter_sodium.crypto_kx_keypair(pkPtr, skPtr)
      }
    }
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: pk),
      "sk": FlutterStandardTypedData.init(bytes: sk)
    ]
  }

  private func crypto_kx_seed_keypair(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let seed = (args["seed"] as! FlutterStandardTypedData).data

    var pk = Data(count: flutter_sodium.crypto_kx_publickeybytes())
    var sk = Data(count: flutter_sodium.crypto_kx_secretkeybytes())
    let ret = pk.withUnsafeMutableBytes { pkPtr in
      sk.withUnsafeMutableBytes { skPtr in
        seed.withUnsafeBytes { seedPtr in
          flutter_sodium.crypto_kx_seed_keypair(pkPtr, skPtr, seedPtr)
        }
      }
    }
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: pk),
      "sk": FlutterStandardTypedData.init(bytes: sk)
    ]
  }

  private func crypto_kx_client_session_keys(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let client_pk = (args["client_pk"] as! FlutterStandardTypedData).data
    let client_sk = (args["client_sk"] as! FlutterStandardTypedData).data
    let server_pk = (args["server_pk"] as! FlutterStandardTypedData).data

    var rx = Data(count: flutter_sodium.crypto_kx_sessionkeybytes())
    var tx = Data(count: flutter_sodium.crypto_kx_sessionkeybytes())
    let ret = rx.withUnsafeMutableBytes { rxPtr in
      tx.withUnsafeMutableBytes { txPtr in
        client_pk.withUnsafeBytes { client_pkPtr in
          client_sk.withUnsafeBytes { client_skPtr in
            server_pk.withUnsafeBytes { server_pkPtr in
              flutter_sodium.crypto_kx_client_session_keys(rxPtr, txPtr, client_pkPtr, client_skPtr, server_pkPtr)
            }
          }
        }
      }
    }
    return error(ret: ret) ?? [
      "rx": FlutterStandardTypedData.init(bytes: rx),
      "tx": FlutterStandardTypedData.init(bytes: tx)
    ]
  }

  private func crypto_kx_server_session_keys(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let server_pk = (args["server_pk"] as! FlutterStandardTypedData).data
    let server_sk = (args["server_sk"] as! FlutterStandardTypedData).data
    let client_pk = (args["client_pk"] as! FlutterStandardTypedData).data

    var rx = Data(count: flutter_sodium.crypto_kx_sessionkeybytes())
    var tx = Data(count: flutter_sodium.crypto_kx_sessionkeybytes())
    let ret = rx.withUnsafeMutableBytes { rxPtr in
      tx.withUnsafeMutableBytes { txPtr in
        server_pk.withUnsafeBytes { server_pkPtr in
          server_sk.withUnsafeBytes { server_skPtr in
            client_pk.withUnsafeBytes { client_pkPtr in
              flutter_sodium.crypto_kx_server_session_keys(rxPtr, txPtr, server_pkPtr, server_skPtr, client_pkPtr)
            }
          }
        }
      }
    }
    return error(ret: ret) ?? [
      "rx": FlutterStandardTypedData.init(bytes: rx),
      "tx": FlutterStandardTypedData.init(bytes: tx)
    ]
  }

  private func crypto_onetimeauth(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let i = (args["in"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var out = Data(count: flutter_sodium.crypto_onetimeauth_bytes())

    let ret = out.withUnsafeMutableBytes { outPtr in
      i.withUnsafeBytes { iPtr in 
        k.withUnsafeBytes { kPtr in 
          flutter_sodium.crypto_onetimeauth(outPtr, iPtr, CUnsignedLongLong(i.count), kPtr)
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: out)
  }

  private func crypto_onetimeauth_verify(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let h = (args["h"] as! FlutterStandardTypedData).data
    let i = (args["in"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    let ret = h.withUnsafeBytes { hPtr in
      i.withUnsafeBytes { iPtr in 
        k.withUnsafeBytes { kPtr in 
          flutter_sodium.crypto_onetimeauth_verify(hPtr, iPtr, CUnsignedLongLong(i.count), kPtr)
        }
      }
    }
    return ret == 0
  }

  private func crypto_onetimeauth_init(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let key = (args["key"] as! FlutterStandardTypedData).data

    var state = Data(count: crypto_onetimeauth_statebytes())
    let ret = state.withUnsafeMutableBytes { statePtr in
      key.withUnsafeBytes { keyPtr in 
        flutter_sodium.crypto_onetimeauth_init(statePtr, keyPtr)
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: state)
  }

  private func crypto_onetimeauth_update(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    let i = (args["in"] as! FlutterStandardTypedData).data

    let ret = state.withUnsafeMutableBytes { statePtr in
      i.withUnsafeBytes { iPtr in 
        flutter_sodium.crypto_onetimeauth_update(statePtr, iPtr, CUnsignedLongLong(i.count))
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: state)
  }

  private func crypto_onetimeauth_final(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data

    var out = Data(count: crypto_onetimeauth_bytes())
    let ret = state.withUnsafeMutableBytes { statePtr in
      out.withUnsafeMutableBytes { outPtr in 
        flutter_sodium.crypto_onetimeauth_final(statePtr, outPtr)
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: out)
  }

  private func crypto_onetimeauth_keygen(call: FlutterMethodCall) -> Any
  {
    var k = Data(count: crypto_onetimeauth_keybytes())
    k.withUnsafeMutableBytes { kPtr in
        flutter_sodium.crypto_onetimeauth_keygen(kPtr)
    }
    return FlutterStandardTypedData.init(bytes: k)
  }
  
  private func crypto_pwhash(call: FlutterMethodCall) -> Any
  {
      let args = call.arguments as! NSDictionary
      let outlen = args["outlen"] as! Int
      let passwd = (args["passwd"] as! FlutterStandardTypedData).data
      let salt = (args["salt"] as! FlutterStandardTypedData).data
      let opslimit = args["opslimit"] as! Int
      let memlimit = args["memlimit"] as! Int
      let alg = args["alg"] as! Int32
      var out = Data(count: outlen)
      
      let ret = out.withUnsafeMutableBytes { outPtr in
          passwd.withUnsafeBytes { passwdPtr in
            salt.withUnsafeBytes { saltPtr in
              flutter_sodium.crypto_pwhash(outPtr, 
                                            CUnsignedLongLong(outlen),
                                            passwdPtr, 
                                            CUnsignedLongLong(passwd.count), 
                                            saltPtr, 
                                            CUnsignedLongLong(opslimit),
                                            size_t(memlimit), 
                                            alg)
            }
          }
      }
      return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: out)
  }
  
  private func crypto_pwhash_str(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let passwd = (args["passwd"] as! FlutterStandardTypedData).data
    let opslimit = args["opslimit"] as! Int
    let memlimit = args["memlimit"] as! Int
    var out = Data(count: flutter_sodium.crypto_pwhash_strbytes())
    
    let ret = out.withUnsafeMutableBytes { outPtr in
      passwd.withUnsafeBytes { passwdPtr in
        flutter_sodium.crypto_pwhash_str(outPtr, 
                                         passwdPtr, 
                                         CUnsignedLongLong(passwd.count), 
                                         CUnsignedLongLong(opslimit), 
                                         size_t(memlimit))
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: out)
  }
  
  private func crypto_pwhash_str_verify(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let str = (args["str"] as! FlutterStandardTypedData).data
    let passwd = (args["passwd"] as! FlutterStandardTypedData).data
    
    let ret = str.withUnsafeBytes { strPtr in
      passwd.withUnsafeBytes { passwdPtr in
        flutter_sodium.crypto_pwhash_str_verify(strPtr, passwdPtr, CUnsignedLongLong(passwd.count))
      }
    }
    return ret == 0
  }
  
  private func crypto_pwhash_str_needs_rehash(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let str = (args["str"] as! FlutterStandardTypedData).data
    let opslimit = args["opslimit"] as! Int
    let memlimit = args["memlimit"] as! Int
    
    let ret = str.withUnsafeBytes { strPtr in
      flutter_sodium.crypto_pwhash_str_needs_rehash(strPtr, CUnsignedLongLong(opslimit), size_t(memlimit))
    }
    return ret != 0
  }

  private func crypto_scalarmult_base(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let n = (args["n"] as! FlutterStandardTypedData).data

    var q = Data(count: crypto_scalarmult_bytes())
    let ret = q.withUnsafeMutableBytes { qPtr in
      n.withUnsafeBytes { nPtr in 
        flutter_sodium.crypto_scalarmult_base(qPtr, nPtr)
      }
    }

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: q)
  }

  private func crypto_scalarmult(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let n = (args["n"] as! FlutterStandardTypedData).data
    let p = (args["p"] as! FlutterStandardTypedData).data

    var q = Data(count: crypto_scalarmult_bytes())
    let ret = q.withUnsafeMutableBytes { qPtr in
      n.withUnsafeBytes { nPtr in 
        p.withUnsafeBytes { pPtr in 
          flutter_sodium.crypto_scalarmult(qPtr, nPtr, pPtr)
        }
      }
    }

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: q)
  }

  private func crypto_secretbox_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var c = Data(count: crypto_secretbox_macbytes() + m.count)
    
    let ret = c.withUnsafeMutableBytes { cPtr in
          m.withUnsafeBytes { mPtr in
            n.withUnsafeBytes { nPtr in
              k.withUnsafeBytes { kPtr in
                flutter_sodium.crypto_secretbox_easy(cPtr,
                                              mPtr, 
                                              CUnsignedLongLong(m.count), 
                                              nPtr, 
                                              kPtr)
              }
            }
          }
        }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: c)
  }

  private func crypto_secretbox_open_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var m = Data(count: c.count - crypto_secretbox_macbytes())

    let ret = m.withUnsafeMutableBytes { mPtr in
          c.withUnsafeBytes { cPtr in
            n.withUnsafeBytes { nPtr in
              k.withUnsafeBytes { kPtr in
                flutter_sodium.crypto_secretbox_open_easy(mPtr,
                                              cPtr, 
                                              CUnsignedLongLong(c.count), 
                                              nPtr, 
                                              kPtr)
              }
            }
          }
        }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: m)
  }

  private func crypto_secretbox_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var c = Data(count: m.count)
    var mac = Data(count: crypto_secretbox_macbytes())

    let ret = c.withUnsafeMutableBytes { cPtr in
          mac.withUnsafeMutableBytes { macPtr in
            m.withUnsafeBytes { mPtr in
              n.withUnsafeBytes { nPtr in
                k.withUnsafeBytes { kPtr in
                  flutter_sodium.crypto_secretbox_detached(cPtr,
                                                macPtr, 
                                                mPtr,
                                                CUnsignedLongLong(m.count), 
                                                nPtr, 
                                                kPtr)
                }
              }
            }
          }
        }

    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: c),
      "mac": FlutterStandardTypedData.init(bytes: mac)
    ]
  }

  private func crypto_secretbox_open_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).data
    let mac = (args["mac"] as! FlutterStandardTypedData).data
    let n = (args["n"] as! FlutterStandardTypedData).data
    let k = (args["k"] as! FlutterStandardTypedData).data

    var m = Data(count: c.count)

    let ret = m.withUnsafeMutableBytes { mPtr in
          c.withUnsafeBytes { cPtr in
            mac.withUnsafeBytes { macPtr in 
              n.withUnsafeBytes { nPtr in
                k.withUnsafeBytes { kPtr in
                  flutter_sodium.crypto_secretbox_open_detached(mPtr,
                                                cPtr, 
                                                macPtr,
                                                CUnsignedLongLong(c.count), 
                                                nPtr, 
                                                kPtr)
                }
              }
            }
          }
        }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: m)
  }

  private func crypto_secretbox_keygen(call: FlutterMethodCall) -> Any
  {
    var k = Data(count: crypto_secretbox_keybytes())
    k.withUnsafeMutableBytes { kPtr in
        flutter_sodium.crypto_secretbox_keygen(kPtr)
    }
    return FlutterStandardTypedData.init(bytes: k)
  }

  private func crypto_shorthash(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let i = (args["in"] as! FlutterStandardTypedData).data
    let key = (args["k"] as! FlutterStandardTypedData).data
    var out = Data(count: flutter_sodium.crypto_shorthash_bytes())

    let ret = out.withUnsafeMutableBytes { outPtr in
      i.withUnsafeBytes { iPtr in 
        key.withUnsafeBytes { keyPtr in
          flutter_sodium.crypto_shorthash(outPtr, iPtr, CUnsignedLongLong(i.count), keyPtr)
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: out)
  }

  private func crypto_shorthash_keygen(call: FlutterMethodCall) -> Any
  {
    var k = Data(count: flutter_sodium.crypto_shorthash_keybytes())
    k.withUnsafeMutableBytes { kPtr in
      flutter_sodium.crypto_shorthash_keygen(kPtr)
    }
    return FlutterStandardTypedData.init(bytes: k)
  }

  private func crypto_sign_seed_keypair(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let seed = (args["seed"] as! FlutterStandardTypedData).data
    
    var pk = Data(count: flutter_sodium.crypto_sign_publickeybytes())
    var sk = Data(count: flutter_sodium.crypto_sign_secretkeybytes())
    let ret = pk.withUnsafeMutableBytes { pkPtr in
      sk.withUnsafeMutableBytes { skPtr in
        seed.withUnsafeBytes { seedPtr in
          flutter_sodium.crypto_sign_seed_keypair(pkPtr, skPtr, seedPtr)
        }
      }
    }
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: pk),
      "sk": FlutterStandardTypedData.init(bytes: sk)
    ]
  }

  private func crypto_sign_keypair(call: FlutterMethodCall) -> Any
  {
    var pk = Data(count: flutter_sodium.crypto_sign_publickeybytes())
    var sk = Data(count: flutter_sodium.crypto_sign_secretkeybytes())
    let ret = pk.withUnsafeMutableBytes { pkPtr in
      sk.withUnsafeMutableBytes { skPtr in
        flutter_sodium.crypto_sign_keypair(pkPtr, skPtr)
      }
    }
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: pk),
      "sk": FlutterStandardTypedData.init(bytes: sk)
    ]
  }

  private func crypto_sign(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).data

    var sm = Data(count: m.count + flutter_sodium.crypto_sign_bytes())
    let ret = sm.withUnsafeMutableBytes { smPtr in 
      m.withUnsafeBytes { mPtr in
        sk.withUnsafeBytes { skPtr in 
          flutter_sodium.crypto_sign(smPtr, nil, mPtr, CUnsignedLongLong(m.count), skPtr)
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: sm)
  }

  private func crypto_sign_open(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let sm = (args["sm"] as! FlutterStandardTypedData).data
    let pk = (args["pk"] as! FlutterStandardTypedData).data

    var m = Data(count: sm.count - flutter_sodium.crypto_sign_bytes())
    let ret = m.withUnsafeMutableBytes { mPtr in 
      sm.withUnsafeBytes { smPtr in
        pk.withUnsafeBytes { pkPtr in 
          flutter_sodium.crypto_sign_open(mPtr, nil, smPtr, CUnsignedLongLong(sm.count), pkPtr)
        }
      }
    }

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: m)
  }

  private func crypto_sign_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).data

    var sig = Data(count: flutter_sodium.crypto_sign_bytes())
    let ret = sig.withUnsafeMutableBytes { sigPtr in 
      m.withUnsafeBytes { mPtr in
        sk.withUnsafeBytes { skPtr in 
          flutter_sodium.crypto_sign_detached(sigPtr, nil, mPtr, CUnsignedLongLong(m.count), skPtr)
        }
      }
    }

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: sig)
  }

  private func crypto_sign_verify_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let sig = (args["sig"] as! FlutterStandardTypedData).data
    let m = (args["m"] as! FlutterStandardTypedData).data
    let pk = (args["pk"] as! FlutterStandardTypedData).data

    let ret = sig.withUnsafeBytes { sigPtr in 
      m.withUnsafeBytes { mPtr in
        pk.withUnsafeBytes { pkPtr in 
          flutter_sodium.crypto_sign_verify_detached(sigPtr, mPtr, CUnsignedLongLong(m.count), pkPtr)
        }
      }
    }

    return ret == 0
  }

  private func crypto_sign_init(call: FlutterMethodCall) -> Any
  {
    var state = Data(count: crypto_sign_statebytes())
    let ret = state.withUnsafeMutableBytes { statePtr in
      flutter_sodium.crypto_sign_init(statePtr)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: state)
  }

  private func crypto_sign_update(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    let m = (args["m"] as! FlutterStandardTypedData).data

    let ret = state.withUnsafeMutableBytes { statePtr in
      m.withUnsafeBytes { mPtr in 
        flutter_sodium.crypto_sign_update(statePtr, mPtr, CUnsignedLongLong(m.count))
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: state)
  }

  private func crypto_sign_final_create(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).data

    var sig = Data(count: crypto_sign_bytes())

    let ret = state.withUnsafeMutableBytes { statePtr in
      sig.withUnsafeMutableBytes { sigPtr in 
        sk.withUnsafeBytes { skPtr in 
          flutter_sodium.crypto_sign_final_create(statePtr, sigPtr, nil, skPtr)
        }
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: sig)
  }

  private func crypto_sign_final_verify(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    var sig = (args["sig"] as! FlutterStandardTypedData).data
    let pk = (args["pk"] as! FlutterStandardTypedData).data

    let ret = state.withUnsafeMutableBytes { statePtr in
      sig.withUnsafeMutableBytes { sigPtr in 
        pk.withUnsafeBytes { pkPtr in 
          flutter_sodium.crypto_sign_final_verify(statePtr, sigPtr, pkPtr)
        }
      }
    }
    return ret == 0
  }

  private func randombytes_buf(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let size = args["size"] as! Int
    var buf = Data(count: size)
    buf.withUnsafeMutableBytes { bufPtr in
      flutter_sodium.randombytes_buf(bufPtr, buf.count)
    }
    return FlutterStandardTypedData.init(bytes: buf)
  }
  
  private func randombytes_buf_deterministic(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let size = args["size"] as! Int
    let seed = (args["seed"] as! FlutterStandardTypedData).data
    
    var buf = Data(count: size)
    buf.withUnsafeMutableBytes { bufPtr in
      seed.withUnsafeBytes { seedPtr in
        flutter_sodium.randombytes_buf_deterministic(bufPtr, buf.count, seedPtr)
      }
    }
    return FlutterStandardTypedData.init(bytes: buf)
  }
  
  private func randombytes_random(call: FlutterMethodCall) -> Any
  {
    return flutter_sodium.randombytes_random()
  }
  
  private func randombytes_uniform(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let upper_bound = args["upper_bound"] as! UInt32
    return flutter_sodium.randombytes_uniform(upper_bound)
  }
  
  private func randombytes_stir(call: FlutterMethodCall) -> Any
  {
    flutter_sodium.randombytes_stir()
    return 0
  }
  
  private func randombytes_close(call: FlutterMethodCall) -> Any
  {
    flutter_sodium.randombytes_close()
    return 0
  }

  private func sodium_version_string(call: FlutterMethodCall) -> Any
  {
    return String(cString: flutter_sodium.sodium_version_string())
  }
}
