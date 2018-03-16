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

      case "crypto_generichash": result(crypto_generichash(call: call))
      case "crypto_generichash_init": result(crypto_generichash_init(call: call))
      case "crypto_generichash_update": result(crypto_generichash_update(call: call))
      case "crypto_generichash_final": result(crypto_generichash_final(call: call))
      case "crypto_generichash_keygen": result(crypto_generichash_keygen(call: call))

      case "crypto_pwhash": result(crypto_pwhash(call: call))
      case "crypto_pwhash_str": result(crypto_pwhash_str(call: call))
      case "crypto_pwhash_str_verify": result(crypto_pwhash_str_verify(call: call))
      case "crypto_pwhash_str_needs_rehash": result(crypto_pwhash_str_needs_rehash(call: call))

      case "crypto_shorthash": result(crypto_shorthash(call: call))
      case "crypto_shorthash_keygen": result(crypto_shorthash_keygen(call: call))

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

    var out = Data(count: flutter_sodium.crypto_auth_bytes());

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
    
    return FlutterMethodNotImplemented
  }
  
  private func crypto_generichash_update(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let state = (args["state"] as! FlutterStandardTypedData).data
    let i = (args["in"] as! FlutterStandardTypedData).data

    return FlutterMethodNotImplemented
  }
  
  private func crypto_generichash_final(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let state = (args["state"] as! FlutterStandardTypedData).data
    let outlen = args["outlen"] as! Int

    return FlutterMethodNotImplemented
  }
  
  private func crypto_generichash_keygen(call: FlutterMethodCall) -> Any
  {
    var k = Data(count: crypto_generichash_keybytes())
    k.withUnsafeMutableBytes { kPtr in
        flutter_sodium.crypto_generichash_keygen(kPtr)
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


  private func crypto_shorthash(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let i = (args["in"] as! FlutterStandardTypedData).data
    let key = (args["k"] as! FlutterStandardTypedData).data
    var out = Data(count: flutter_sodium.crypto_shorthash_bytes());

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
