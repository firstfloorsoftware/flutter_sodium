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
