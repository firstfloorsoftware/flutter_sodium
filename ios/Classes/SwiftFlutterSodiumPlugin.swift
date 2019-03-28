import Flutter
import UIKit

extension FlutterStandardTypedData {
  var uint8Array: Array<UInt8> {
    return Array(data)
  }
  var int8Array: Array<Int8> {
    return data.withUnsafeBytes { raw in
      [Int8](raw.bindMemory(to: Int8.self))
    }
  }
}

extension Data {
  @inlinable mutating func asCryptoOnetimeauthState<ResultType>(_ body: (inout crypto_onetimeauth_state) throws -> ResultType) rethrows -> ResultType {
    return try withUnsafeMutableBytes { bytes in
      try body(&bytes.baseAddress!.bindMemory(to: crypto_onetimeauth_state.self, capacity: 1).pointee)
    }
  }

  @inlinable mutating func asCryptoSignState<ResultType>(_ body: (inout crypto_sign_state) throws -> ResultType) rethrows -> ResultType {
    return try withUnsafeMutableBytes { bytes in
      try body(&bytes.baseAddress!.bindMemory(to: crypto_sign_state.self, capacity: 1).pointee)
    }
  }
}

extension crypto_onetimeauth_state {
  init?(array: Array<UInt8>) {
    guard array.count == MemoryLayout<crypto_onetimeauth_state>.size else {
      return nil
    }

    self = array.withUnsafeBytes { data in
      data.load(as: crypto_onetimeauth_state.self)
    }
  }

  init(fromData data: inout Data) {
    self = data.withUnsafeMutableBytes { data in
      data.baseAddress!.bindMemory(to: crypto_onetimeauth_state.self, capacity: 1).pointee
    }
  }
}

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

    if (shouldRunInBackground(call)) {
      // run on background thread
      DispatchQueue.global(qos: .background).async {
        let r = self.execute(call)

        DispatchQueue.main.async {
          result(r)
        }
      }
    }
    else {
      // run on UI thread
      result(execute(call))
    }
  }

  private func shouldRunInBackground(_ call: FlutterMethodCall) -> Bool
  {
    if (call.arguments != nil)
    {
      let args = call.arguments as! NSDictionary
      let bgThread = args["bgThread"] as? Bool
      return (bgThread != nil && bgThread!)
    }
    return false
  }

  private func execute(_ call: FlutterMethodCall) -> Any
  {
    switch call.method {
    case "crypto_aead_chacha20poly1305_encrypt": return crypto_aead_chacha20poly1305_encrypt(call:call)
    case "crypto_aead_chacha20poly1305_decrypt": return crypto_aead_chacha20poly1305_decrypt(call:call)
    case "crypto_aead_chacha20poly1305_encrypt_detached": return crypto_aead_chacha20poly1305_encrypt_detached(call:call)
    case "crypto_aead_chacha20poly1305_decrypt_detached": return crypto_aead_chacha20poly1305_decrypt_detached(call:call)
    case "crypto_aead_chacha20poly1305_keygen": return crypto_aead_chacha20poly1305_keygen(call:call)

    case "crypto_aead_chacha20poly1305_ietf_encrypt": return crypto_aead_chacha20poly1305_ietf_encrypt(call:call)
    case "crypto_aead_chacha20poly1305_ietf_decrypt": return crypto_aead_chacha20poly1305_ietf_decrypt(call:call)
    case "crypto_aead_chacha20poly1305_ietf_encrypt_detached": return crypto_aead_chacha20poly1305_ietf_encrypt_detached(call:call)
    case "crypto_aead_chacha20poly1305_ietf_decrypt_detached": return crypto_aead_chacha20poly1305_ietf_decrypt_detached(call:call)
    case "crypto_aead_chacha20poly1305_ietf_keygen": return crypto_aead_chacha20poly1305_ietf_keygen(call:call)

    case "crypto_aead_xchacha20poly1305_ietf_encrypt": return crypto_aead_xchacha20poly1305_ietf_encrypt(call:call)
    case "crypto_aead_xchacha20poly1305_ietf_decrypt": return crypto_aead_xchacha20poly1305_ietf_decrypt(call:call)
    case "crypto_aead_xchacha20poly1305_ietf_encrypt_detached": return crypto_aead_xchacha20poly1305_ietf_encrypt_detached(call:call)
    case "crypto_aead_xchacha20poly1305_ietf_decrypt_detached": return crypto_aead_xchacha20poly1305_ietf_decrypt_detached(call:call)
    case "crypto_aead_xchacha20poly1305_ietf_keygen": return crypto_aead_xchacha20poly1305_ietf_keygen(call:call)

    case "crypto_auth": return crypto_auth(call:call)
    case "crypto_auth_verify": return crypto_auth_verify(call:call)
    case "crypto_auth_keygen": return crypto_auth_keygen(call:call)

    case "crypto_box_seed_keypair": return crypto_box_seed_keypair(call: call)
    case "crypto_box_keypair": return crypto_box_keypair(call: call)
    case "crypto_box_easy": return crypto_box_easy(call:call)
    case "crypto_box_open_easy": return crypto_box_open_easy(call:call)
    case "crypto_box_detached": return crypto_box_detached(call:call)
    case "crypto_box_open_detached": return crypto_box_open_detached(call:call)
    case "crypto_box_beforenm": return crypto_box_beforenm(call:call)
    case "crypto_box_easy_afternm": return crypto_box_easy_afternm(call:call)
    case "crypto_box_open_easy_afternm": return crypto_box_open_easy_afternm(call:call)
    case "crypto_box_detached_afternm": return crypto_box_detached_afternm(call:call)
    case "crypto_box_open_detached_afternm": return crypto_box_open_detached_afternm(call:call)

    case "crypto_box_seal": return crypto_box_seal(call: call)
    case "crypto_box_seal_open": return crypto_box_seal_open(call: call)

    case "crypto_box_curve25519xchacha20poly1305_seed_keypair": return crypto_box_curve25519xchacha20poly1305_seed_keypair(call: call)
    case "crypto_box_curve25519xchacha20poly1305_keypair": return crypto_box_curve25519xchacha20poly1305_keypair(call: call)
    case "crypto_box_curve25519xchacha20poly1305_easy": return crypto_box_curve25519xchacha20poly1305_easy(call:call)
    case "crypto_box_curve25519xchacha20poly1305_open_easy": return crypto_box_curve25519xchacha20poly1305_open_easy(call:call)
    case "crypto_box_curve25519xchacha20poly1305_detached": return crypto_box_curve25519xchacha20poly1305_detached(call:call)
    case "crypto_box_curve25519xchacha20poly1305_open_detached": return crypto_box_curve25519xchacha20poly1305_open_detached(call:call)
    case "crypto_box_curve25519xchacha20poly1305_beforenm": return crypto_box_curve25519xchacha20poly1305_beforenm(call:call)
    case "crypto_box_curve25519xchacha20poly1305_easy_afternm": return crypto_box_curve25519xchacha20poly1305_easy_afternm(call:call)
    case "crypto_box_curve25519xchacha20poly1305_open_easy_afternm": return crypto_box_curve25519xchacha20poly1305_open_easy_afternm(call:call)
    case "crypto_box_curve25519xchacha20poly1305_detached_afternm": return crypto_box_curve25519xchacha20poly1305_detached_afternm(call:call)
    case "crypto_box_curve25519xchacha20poly1305_open_detached_afternm": return crypto_box_curve25519xchacha20poly1305_open_detached_afternm(call:call)

    case "crypto_box_curve25519xchacha20poly1305_seal": return crypto_box_curve25519xchacha20poly1305_seal(call: call)
    case "crypto_box_curve25519xchacha20poly1305_seal_open": return crypto_box_curve25519xchacha20poly1305_seal_open(call: call)

    case "crypto_generichash": return crypto_generichash(call: call)
    case "crypto_generichash_init": return crypto_generichash_init(call: call)
    case "crypto_generichash_update": return crypto_generichash_update(call: call)
    case "crypto_generichash_final": return crypto_generichash_final(call: call)
    case "crypto_generichash_keygen": return crypto_generichash_keygen(call: call)

    case "crypto_kdf_keygen": return crypto_kdf_keygen(call: call)
    case "crypto_kdf_derive_from_key": return crypto_kdf_derive_from_key(call: call)

    case "crypto_kx_keypair": return crypto_kx_keypair(call: call)
    case "crypto_kx_seed_keypair": return crypto_kx_seed_keypair(call: call)
    case "crypto_kx_client_session_keys": return crypto_kx_client_session_keys(call: call)
    case "crypto_kx_server_session_keys": return crypto_kx_server_session_keys(call: call)

    case "crypto_onetimeauth": return crypto_onetimeauth(call: call)
    case "crypto_onetimeauth_verify": return crypto_onetimeauth_verify(call: call)
    case "crypto_onetimeauth_init": return crypto_onetimeauth_init(call: call)
    case "crypto_onetimeauth_update": return crypto_onetimeauth_update(call: call)
    case "crypto_onetimeauth_final": return crypto_onetimeauth_final(call: call)
    case "crypto_onetimeauth_keygen": return crypto_onetimeauth_keygen(call: call)

    case "crypto_pwhash": return crypto_pwhash(call: call)
    case "crypto_pwhash_str": return crypto_pwhash_str(call: call)
    case "crypto_pwhash_str_verify": return crypto_pwhash_str_verify(call: call)
    case "crypto_pwhash_str_needs_rehash": return crypto_pwhash_str_needs_rehash(call: call)

    case "crypto_scalarmult_base": return crypto_scalarmult_base(call: call)
    case "crypto_scalarmult": return crypto_scalarmult(call: call)

    case "crypto_secretbox_easy": return crypto_secretbox_easy(call: call)
    case "crypto_secretbox_open_easy": return crypto_secretbox_open_easy(call: call)
    case "crypto_secretbox_detached": return crypto_secretbox_detached(call: call)
    case "crypto_secretbox_open_detached": return crypto_secretbox_open_detached(call: call)
    case "crypto_secretbox_keygen": return crypto_secretbox_keygen(call: call)

    case "crypto_shorthash": return crypto_shorthash(call: call)
    case "crypto_shorthash_keygen": return crypto_shorthash_keygen(call: call)

    case "crypto_sign_seed_keypair": return crypto_sign_seed_keypair(call: call)
    case "crypto_sign_keypair": return crypto_sign_keypair(call: call)
    case "crypto_sign": return crypto_sign(call: call)
    case "crypto_sign_open": return crypto_sign_open(call: call)
    case "crypto_sign_detached": return crypto_sign_detached(call: call)
    case "crypto_sign_verify_detached": return crypto_sign_verify_detached(call: call)
    case "crypto_sign_init": return crypto_sign_init(call: call)
    case "crypto_sign_update": return crypto_sign_update(call: call)
    case "crypto_sign_final_create": return crypto_sign_final_create(call: call)
    case "crypto_sign_final_verify": return crypto_sign_final_verify(call: call)
    case "crypto_sign_ed25519_sk_to_curve25519": return crypto_sign_ed25519_sk_to_curve25519(call: call)

    case "randombytes_buf": return randombytes_buf(call: call)
    case "randombytes_buf_deterministic": return randombytes_buf_deterministic(call: call)
    case "randombytes_random": return randombytes_random(call: call)
    case "randombytes_uniform": return randombytes_uniform(call: call)

    case "sodium_version_string": return sodium_version_string(call: call)

    default: return FlutterMethodNotImplemented
    }
  }

  private func error(ret: Int32, function: String = #function) -> FlutterError?
  {
    if (ret != 0) {
      return FlutterError.init(code: "Failure", message: "\(function) returns \(ret)", details: nil)
    }
    return nil
  }

  private func crypto_aead_chacha20poly1305_encrypt(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count + flutter_sodium.crypto_aead_chacha20poly1305_abytes())
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_encrypt(&c, nil, m, CUnsignedLongLong(m.count), ad, CUnsignedLongLong(ad.count), nil, npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_encrypt(&c, nil, m, CUnsignedLongLong(m.count), nil, 0, nil, npub, k)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_aead_chacha20poly1305_decrypt(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - flutter_sodium.crypto_aead_chacha20poly1305_abytes())
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_decrypt(&m, nil, nil, c, CUnsignedLongLong(c.count), ad, CUnsignedLongLong(ad.count), npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_decrypt(&m, nil, nil, c, CUnsignedLongLong(c.count), nil, 0, npub, k)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_aead_chacha20poly1305_encrypt_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count)
    var mac = [UInt8](repeating: 0, count: flutter_sodium.crypto_aead_chacha20poly1305_abytes())
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_encrypt_detached(&c, &mac, nil, m, CUnsignedLongLong(m.count), ad, CUnsignedLongLong(ad.count), nil, npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_encrypt_detached(&c, &mac, nil, m, CUnsignedLongLong(m.count), nil, 0, nil, npub, k)
    }

    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: Data(c)),
      "mac": FlutterStandardTypedData.init(bytes: Data(mac))
    ]
  }

  private func crypto_aead_chacha20poly1305_decrypt_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let mac = (args["mac"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count)
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_decrypt_detached(&m, nil, c, CUnsignedLongLong(c.count), mac, ad, CUnsignedLongLong(ad.count), npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_decrypt_detached(&m, nil, c, CUnsignedLongLong(c.count), mac, nil, 0, npub, k)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_aead_chacha20poly1305_keygen(call: FlutterMethodCall) -> Any
  {
    var k = [UInt8](repeating: 0, count: flutter_sodium.crypto_aead_chacha20poly1305_keybytes())
    flutter_sodium.crypto_aead_chacha20poly1305_keygen(&k)
    return FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_aead_chacha20poly1305_ietf_encrypt(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count + flutter_sodium.crypto_aead_chacha20poly1305_ietf_abytes())
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_ietf_encrypt(&c, nil, m, CUnsignedLongLong(m.count), ad, CUnsignedLongLong(ad.count), nil, npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_ietf_encrypt(&c, nil, m, CUnsignedLongLong(m.count), nil, 0, nil, npub, k)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_aead_chacha20poly1305_ietf_decrypt(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - flutter_sodium.crypto_aead_chacha20poly1305_ietf_abytes())
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_ietf_decrypt(&m, nil, nil, c, CUnsignedLongLong(c.count), ad, CUnsignedLongLong(ad.count), npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_ietf_decrypt(&m, nil, nil, c, CUnsignedLongLong(c.count), nil, 0, npub, k)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_aead_chacha20poly1305_ietf_encrypt_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count)
    var mac = [UInt8](repeating: 0, count: flutter_sodium.crypto_aead_chacha20poly1305_ietf_abytes())
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(&c, &mac, nil, m, CUnsignedLongLong(m.count), ad, CUnsignedLongLong(ad.count), nil, npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(&c, &mac, nil, m, CUnsignedLongLong(m.count), nil, 0, nil, npub, k)
    }

    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: Data(c)),
      "mac": FlutterStandardTypedData.init(bytes: Data(mac))
    ]
  }

  private func crypto_aead_chacha20poly1305_ietf_decrypt_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let mac = (args["mac"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count)
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(&m, nil, c, CUnsignedLongLong(c.count), mac, ad, CUnsignedLongLong(ad.count), npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(&m, nil, c, CUnsignedLongLong(c.count), mac, nil, 0, npub, k)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_aead_chacha20poly1305_ietf_keygen(call: FlutterMethodCall) -> Any
  {
    var k = [UInt8](repeating: 0, count: flutter_sodium.crypto_aead_chacha20poly1305_ietf_keybytes())

    flutter_sodium.crypto_aead_chacha20poly1305_ietf_keygen(&k)
    return FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_aead_xchacha20poly1305_ietf_encrypt(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count + flutter_sodium.crypto_aead_xchacha20poly1305_ietf_abytes())
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(&c, nil, m, CUnsignedLongLong(m.count), ad, CUnsignedLongLong(ad.count), nil, npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(&c, nil, m, CUnsignedLongLong(m.count), nil, 0, nil, npub, k)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_aead_xchacha20poly1305_ietf_decrypt(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - flutter_sodium.crypto_aead_xchacha20poly1305_ietf_abytes())
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(&m, nil, nil, c, CUnsignedLongLong(c.count), ad, CUnsignedLongLong(ad.count), npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(&m, nil, nil, c, CUnsignedLongLong(c.count), nil, 0, npub, k)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_aead_xchacha20poly1305_ietf_encrypt_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count)
    var mac = [UInt8](repeating: 0, count: flutter_sodium.crypto_aead_xchacha20poly1305_ietf_abytes())
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(&c, &mac, nil, m, CUnsignedLongLong(m.count), ad, CUnsignedLongLong(ad.count), nil, npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(&c, &mac, nil, m, CUnsignedLongLong(m.count), nil, 0, nil, npub, k)
    }

    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: Data(c)),
      "mac": FlutterStandardTypedData.init(bytes: Data(mac))
    ]
  }

  private func crypto_aead_xchacha20poly1305_ietf_decrypt_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let mac = (args["mac"] as! FlutterStandardTypedData).uint8Array
    let ad = (args["ad"] as? FlutterStandardTypedData)?.uint8Array
    let npub = (args["npub"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count)
    var ret: Int32 = -1

    if let ad = ad {
      ret = flutter_sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(&m, nil, c, CUnsignedLongLong(c.count), mac, ad, CUnsignedLongLong(ad.count), npub, k)
    }
    else {
      ret = flutter_sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(&m, nil, c, CUnsignedLongLong(c.count), mac, nil, 0, npub, k)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_aead_xchacha20poly1305_ietf_keygen(call: FlutterMethodCall) -> Any
  {
    var k = [UInt8](repeating: 0, count: flutter_sodium.crypto_aead_xchacha20poly1305_ietf_keybytes())
    flutter_sodium.crypto_aead_xchacha20poly1305_ietf_keygen(&k)
    return FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_auth(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let i = (args["in"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var out = [UInt8](repeating: 0, count: flutter_sodium.crypto_auth_bytes())

    let ret = flutter_sodium.crypto_auth(&out, i, CUnsignedLongLong(i.count), k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(out))
  }

  private func crypto_auth_verify(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let h = (args["h"] as! FlutterStandardTypedData).uint8Array
    let i = (args["in"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    let ret = flutter_sodium.crypto_auth_verify(h, i, CUnsignedLongLong(i.count), k)
    return ret == 0
  }

  private func crypto_auth_keygen(call: FlutterMethodCall) -> Any
  {
    var k = [UInt8](repeating: 0, count: flutter_sodium.crypto_auth_keybytes())
    flutter_sodium.crypto_auth_keygen(&k)
    return FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_box_seed_keypair(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let seed = (args["seed"] as! FlutterStandardTypedData).uint8Array

    var pk = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_publickeybytes())
    var sk = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_secretkeybytes())
    let ret = flutter_sodium.crypto_box_seed_keypair(&pk, &sk, seed)
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: Data(pk)),
      "sk": FlutterStandardTypedData.init(bytes: Data(sk))
    ]
  }

  private func crypto_box_keypair(call: FlutterMethodCall) -> Any
  {
    var pk = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_publickeybytes())
    var sk = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_secretkeybytes())
    let ret = flutter_sodium.crypto_box_keypair(&pk, &sk)
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: Data(pk)),
      "sk": FlutterStandardTypedData.init(bytes: Data(sk))
    ]
  }

  private func crypto_box_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_macbytes() + m.count)

    let ret = flutter_sodium.crypto_box_easy(&c, m, CUnsignedLongLong(m.count), n, pk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_box_open_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - flutter_sodium.crypto_box_macbytes())

    let ret = flutter_sodium.crypto_box_open_easy(&m, c, CUnsignedLongLong(c.count), n, pk, sk)

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_box_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count)
    var mac = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_macbytes())

    let ret = flutter_sodium.crypto_box_detached(&c, &mac, m, CUnsignedLongLong(m.count), n, pk, sk)
    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: Data(c)),
      "mac": FlutterStandardTypedData.init(bytes: Data(mac))
    ]
  }

  private func crypto_box_open_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let mac = (args["mac"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count)

    let ret = flutter_sodium.crypto_box_open_detached(&m, c, mac, CUnsignedLongLong(c.count), n, pk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_box_beforenm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var k = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_beforenmbytes())
    let ret = flutter_sodium.crypto_box_beforenm(&k, pk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_box_easy_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_macbytes() + m.count)

    let ret = flutter_sodium.crypto_box_easy_afternm(&c, m, CUnsignedLongLong(m.count), n, k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_box_open_easy_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - flutter_sodium.crypto_box_macbytes())

    let ret = flutter_sodium.crypto_box_open_easy_afternm(&m, c, CUnsignedLongLong(c.count), n, k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_box_detached_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count)
    var mac = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_macbytes())

    let ret = flutter_sodium.crypto_box_detached_afternm(&c, &mac, m, CUnsignedLongLong(m.count), n, k)
    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: Data(c)),
      "mac": FlutterStandardTypedData.init(bytes: Data(mac))
    ]
  }

  private func crypto_box_open_detached_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let mac = (args["mac"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count)

    let ret = flutter_sodium.crypto_box_open_detached_afternm(&m, c, mac, CUnsignedLongLong(c.count), n, k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_box_seal(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count + flutter_sodium.crypto_box_sealbytes())

    let ret = flutter_sodium.crypto_box_seal(&c, m, CUnsignedLongLong(m.count), pk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_box_seal_open(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - flutter_sodium.crypto_box_sealbytes())

    let ret = flutter_sodium.crypto_box_seal_open(&m, c, CUnsignedLongLong(c.count), pk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_box_curve25519xchacha20poly1305_seed_keypair(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let seed = (args["seed"] as! FlutterStandardTypedData).uint8Array

    var pk = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_curve25519xchacha20poly1305_publickeybytes())
    var sk = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_curve25519xchacha20poly1305_secretkeybytes())
    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_seed_keypair(&pk, &sk, seed)
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: Data(pk)),
      "sk": FlutterStandardTypedData.init(bytes: Data(sk))
    ]
  }

  private func crypto_box_curve25519xchacha20poly1305_keypair(call: FlutterMethodCall) -> Any
  {
    var pk = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_curve25519xchacha20poly1305_publickeybytes())
    var sk = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_curve25519xchacha20poly1305_secretkeybytes())
    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_keypair(&pk, &sk)
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: Data(pk)),
      "sk": FlutterStandardTypedData.init(bytes: Data(sk))
    ]
  }

  private func crypto_box_curve25519xchacha20poly1305_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_curve25519xchacha20poly1305_macbytes() + m.count)

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_easy(&c, m, CUnsignedLongLong(m.count), n, pk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_box_curve25519xchacha20poly1305_open_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - flutter_sodium.crypto_box_curve25519xchacha20poly1305_macbytes())

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_open_easy(&m, c, CUnsignedLongLong(c.count), n, pk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_box_curve25519xchacha20poly1305_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count)
    var mac = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_curve25519xchacha20poly1305_macbytes())

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_detached(&c, &mac, m, CUnsignedLongLong(m.count), n, pk, sk)
    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: Data(c)),
      "mac": FlutterStandardTypedData.init(bytes: Data(mac))
    ]
  }

  private func crypto_box_curve25519xchacha20poly1305_open_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let mac = (args["mac"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count)

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_open_detached(&m, c, mac, CUnsignedLongLong(c.count), n, pk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_box_curve25519xchacha20poly1305_beforenm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var k = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_curve25519xchacha20poly1305_beforenmbytes())
    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_beforenm(&k, pk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_box_curve25519xchacha20poly1305_easy_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_curve25519xchacha20poly1305_macbytes() + m.count)

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_easy_afternm(&c, m, CUnsignedLongLong(m.count), n, k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_box_curve25519xchacha20poly1305_open_easy_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - flutter_sodium.crypto_box_curve25519xchacha20poly1305_macbytes())

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(&m, c, CUnsignedLongLong(c.count), n, k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_box_curve25519xchacha20poly1305_detached_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count)
    var mac = [UInt8](repeating: 0, count: flutter_sodium.crypto_box_curve25519xchacha20poly1305_macbytes())

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_detached_afternm(&c, &mac, m, CUnsignedLongLong(m.count), n, k)
    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: Data(c)),
      "mac": FlutterStandardTypedData.init(bytes: Data(mac))
    ]
  }

  private func crypto_box_curve25519xchacha20poly1305_open_detached_afternm(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let mac = (args["mac"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count)

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_open_detached_afternm(&m, c, mac, CUnsignedLongLong(c.count), n, k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_box_curve25519xchacha20poly1305_seal(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count + flutter_sodium.crypto_box_curve25519xchacha20poly1305_sealbytes())

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_seal(&c, m, CUnsignedLongLong(m.count), pk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_box_curve25519xchacha20poly1305_seal_open(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - flutter_sodium.crypto_box_curve25519xchacha20poly1305_sealbytes())

    let ret = flutter_sodium.crypto_box_curve25519xchacha20poly1305_seal_open(&m, c, CUnsignedLongLong(c.count), pk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_generichash(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let outlen = args["outlen"] as! Int
    let i = (args["in"] as! FlutterStandardTypedData).uint8Array
    let key = (args["key"] as? FlutterStandardTypedData)?.uint8Array
    var out = [UInt8](repeating: 0, count: outlen)
    var ret: Int32 = -1

    if let key = key {
      ret = flutter_sodium.crypto_generichash(&out, outlen, i, CUnsignedLongLong(i.count), key, key.count)
    }
    else {
      ret = flutter_sodium.crypto_generichash(&out, outlen, i, CUnsignedLongLong(i.count), nil, 0)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(out))
  }

  private func crypto_generichash_init(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let key = (args["key"] as? FlutterStandardTypedData)?.uint8Array
    let outlen = args["outlen"] as! Int
    var ret: Int32 = -1
    var state = [UInt8](repeating: 0, count: crypto_generichash_statebytes())

    if let key = key {
      state.withUnsafeMutableBytes { state in
        ret = flutter_sodium.crypto_generichash_init(OpaquePointer(state.baseAddress), key, key.count, outlen)
      }
    }
    else {
      state.withUnsafeMutableBytes { state in
        ret = flutter_sodium.crypto_generichash_init(OpaquePointer(state.baseAddress), nil, 0, outlen)
      }
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(state))
  }

  private func crypto_generichash_update(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).uint8Array
    let i = (args["in"] as! FlutterStandardTypedData).uint8Array

    let ret = state.withUnsafeMutableBytes { state in
      flutter_sodium.crypto_generichash_update(OpaquePointer(state.baseAddress), i, CUnsignedLongLong(i.count))
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(state))
  }

  private func crypto_generichash_final(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).uint8Array
    let outlen = args["outlen"] as! Int

    var out = [UInt8](repeating: 0, count: outlen)

    let ret = state.withUnsafeMutableBytes { state in
      flutter_sodium.crypto_generichash_final(OpaquePointer(state.baseAddress), &out, outlen)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(out))
  }

  private func crypto_generichash_keygen(call: FlutterMethodCall) -> Any
  {
    var k = [UInt8](repeating: 0, count: crypto_generichash_keybytes())
    flutter_sodium.crypto_generichash_keygen(&k)
    return FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_kdf_keygen(call: FlutterMethodCall) -> Any
  {
    var k = [UInt8](repeating: 0, count: crypto_kdf_keybytes())
    flutter_sodium.crypto_kdf_keygen(&k)
    return FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_kdf_derive_from_key(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let subkey_len = args["subkey_len"] as! Int
    let subkey_id = args["subkey_id"] as! UInt64
    let ctx = (args["ctx"] as! FlutterStandardTypedData).int8Array
    let key = (args["key"] as! FlutterStandardTypedData).uint8Array

    var subkey = [UInt8](repeating: 0, count: subkey_len)
    let ret = flutter_sodium.crypto_kdf_derive_from_key(&subkey, size_t(subkey_len), subkey_id, ctx, key)

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(subkey))
  }

  private func crypto_kx_keypair(call: FlutterMethodCall) -> Any
  {
    var pk = [UInt8](repeating: 0, count: flutter_sodium.crypto_kx_publickeybytes())
    var sk = [UInt8](repeating: 0, count: flutter_sodium.crypto_kx_secretkeybytes())
    let ret = flutter_sodium.crypto_kx_keypair(&pk, &sk)
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: Data(pk)),
      "sk": FlutterStandardTypedData.init(bytes: Data(sk))
    ]
  }

  private func crypto_kx_seed_keypair(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let seed = (args["seed"] as! FlutterStandardTypedData).uint8Array

    var pk = [UInt8](repeating: 0, count: flutter_sodium.crypto_kx_publickeybytes())
    var sk = [UInt8](repeating: 0, count: flutter_sodium.crypto_kx_secretkeybytes())
    let ret = flutter_sodium.crypto_kx_seed_keypair(&pk, &sk, seed)
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: Data(pk)),
      "sk": FlutterStandardTypedData.init(bytes: Data(sk))
    ]
  }

  private func crypto_kx_client_session_keys(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let client_pk = (args["client_pk"] as! FlutterStandardTypedData).uint8Array
    let client_sk = (args["client_sk"] as! FlutterStandardTypedData).uint8Array
    let server_pk = (args["server_pk"] as! FlutterStandardTypedData).uint8Array

    var rx = [UInt8](repeating: 0, count: flutter_sodium.crypto_kx_sessionkeybytes())
    var tx = [UInt8](repeating: 0, count: flutter_sodium.crypto_kx_sessionkeybytes())
    let ret = flutter_sodium.crypto_kx_client_session_keys(&rx, &tx, client_pk, client_sk, server_pk)
    return error(ret: ret) ?? [
      "rx": FlutterStandardTypedData.init(bytes: Data(rx)),
      "tx": FlutterStandardTypedData.init(bytes: Data(tx))
    ]
  }

  private func crypto_kx_server_session_keys(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let server_pk = (args["server_pk"] as! FlutterStandardTypedData).uint8Array
    let server_sk = (args["server_sk"] as! FlutterStandardTypedData).uint8Array
    let client_pk = (args["client_pk"] as! FlutterStandardTypedData).uint8Array

    var rx = [UInt8](repeating: 0, count: flutter_sodium.crypto_kx_sessionkeybytes())
    var tx = [UInt8](repeating: 0, count: flutter_sodium.crypto_kx_sessionkeybytes())
    let ret = flutter_sodium.crypto_kx_server_session_keys(&rx, &tx, server_pk, server_sk, client_pk)
    return error(ret: ret) ?? [
      "rx": FlutterStandardTypedData.init(bytes: Data(rx)),
      "tx": FlutterStandardTypedData.init(bytes: Data(tx))
    ]
  }

  private func crypto_onetimeauth(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let i = (args["in"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var out = [UInt8](repeating: 0, count: flutter_sodium.crypto_onetimeauth_bytes())

    let ret = flutter_sodium.crypto_onetimeauth(&out, i, CUnsignedLongLong(i.count), k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(out))
  }

  private func crypto_onetimeauth_verify(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let h = (args["h"] as! FlutterStandardTypedData).uint8Array
    let i = (args["in"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    let ret = flutter_sodium.crypto_onetimeauth_verify(h, i, CUnsignedLongLong(i.count), k)
    return ret == 0
  }

  private func crypto_onetimeauth_init(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let key = (args["key"] as! FlutterStandardTypedData).uint8Array

    var state = crypto_onetimeauth_state()
    let ret = flutter_sodium.crypto_onetimeauth_init(&state, key)

    return error(ret: ret) ?? withUnsafeBytes(of: &state) { state in
      FlutterStandardTypedData.init(bytes: Data(state))
    }
  }

  private func crypto_onetimeauth_update(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    let i = (args["in"] as! FlutterStandardTypedData).uint8Array

    let ret = state.asCryptoOnetimeauthState { state in
      flutter_sodium.crypto_onetimeauth_update(&state, i, CUnsignedLongLong(i.count))
    }

    //    let ret = flutter_sodium.crypto_onetimeauth_update(&state, i, CUnsignedLongLong(i.count))
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: state)
  }

  private func crypto_onetimeauth_final(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data

    var out = [UInt8](repeating: 0, count: crypto_onetimeauth_bytes())
    let ret = state.asCryptoOnetimeauthState { state in
      flutter_sodium.crypto_onetimeauth_final(&state, &out)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(out))
  }

  private func crypto_onetimeauth_keygen(call: FlutterMethodCall) -> Any
  {
    var k = [UInt8](repeating: 0, count: crypto_onetimeauth_keybytes())
    flutter_sodium.crypto_onetimeauth_keygen(&k)
    return FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_pwhash(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let outlen = args["outlen"] as! Int
    let passwd = (args["passwd"] as! FlutterStandardTypedData).int8Array
    let salt = (args["salt"] as! FlutterStandardTypedData).uint8Array
    let opslimit = args["opslimit"] as! Int
    let memlimit = args["memlimit"] as! Int
    let alg = args["alg"] as! Int32
    var out = [UInt8](repeating: 0, count: outlen)

    let ret = flutter_sodium.crypto_pwhash(&out, CUnsignedLongLong(outlen), passwd, CUnsignedLongLong(passwd.count), salt, CUnsignedLongLong(opslimit), size_t(memlimit),alg)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(out))
  }

  private func crypto_pwhash_str(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let passwd = (args["passwd"] as! FlutterStandardTypedData).int8Array
    let opslimit = args["opslimit"] as! Int
    let memlimit = args["memlimit"] as! Int
    var out = [Int8](repeating: 0, count: flutter_sodium.crypto_pwhash_strbytes())

    let ret = flutter_sodium.crypto_pwhash_str(&out, passwd, CUnsignedLongLong(passwd.count), CUnsignedLongLong(opslimit), size_t(memlimit))
    return error(ret: ret) ?? out.withUnsafeBytes { out in
      FlutterStandardTypedData.init(bytes: Data(bytes: out.baseAddress!, count: out.count))
    }
  }

  private func crypto_pwhash_str_verify(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let str = (args["str"] as! FlutterStandardTypedData).int8Array
    let passwd = (args["passwd"] as! FlutterStandardTypedData).int8Array

    let ret = flutter_sodium.crypto_pwhash_str_verify(str, passwd, CUnsignedLongLong(passwd.count))
    return ret == 0
  }

  private func crypto_pwhash_str_needs_rehash(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let str = (args["str"] as! FlutterStandardTypedData).int8Array
    let opslimit = args["opslimit"] as! Int
    let memlimit = args["memlimit"] as! Int

    let ret = flutter_sodium.crypto_pwhash_str_needs_rehash(str, CUnsignedLongLong(opslimit), size_t(memlimit))
    return ret != 0
  }

  private func crypto_scalarmult_base(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array

    var q = [UInt8](repeating: 0, count: crypto_scalarmult_bytes())
    let ret = flutter_sodium.crypto_scalarmult_base(&q, n)

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(q))
  }

  private func crypto_scalarmult(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let p = (args["p"] as! FlutterStandardTypedData).uint8Array

    var q = [UInt8](repeating: 0, count: crypto_scalarmult_bytes())
    let ret = flutter_sodium.crypto_scalarmult(&q, n, p)

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(q))
  }

  private func crypto_secretbox_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: crypto_secretbox_macbytes() + m.count)

    let ret = flutter_sodium.crypto_secretbox_easy(&c, m, CUnsignedLongLong(m.count), n, k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(c))
  }

  private func crypto_secretbox_open_easy(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count - crypto_secretbox_macbytes())

    let ret = flutter_sodium.crypto_secretbox_open_easy(&m, c, CUnsignedLongLong(c.count), n, k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_secretbox_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var c = [UInt8](repeating: 0, count: m.count)
    var mac = [UInt8](repeating: 0, count: crypto_secretbox_macbytes())

    let ret = flutter_sodium.crypto_secretbox_detached(&c, &mac, m, CUnsignedLongLong(m.count), n, k)

    return error(ret: ret) ?? [
      "c": FlutterStandardTypedData.init(bytes: Data(c)),
      "mac": FlutterStandardTypedData.init(bytes: Data(mac))
    ]
  }

  private func crypto_secretbox_open_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let c = (args["c"] as! FlutterStandardTypedData).uint8Array
    let mac = (args["mac"] as! FlutterStandardTypedData).uint8Array
    let n = (args["n"] as! FlutterStandardTypedData).uint8Array
    let k = (args["k"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: c.count)

    let ret = flutter_sodium.crypto_secretbox_open_detached(&m, c, mac, CUnsignedLongLong(c.count), n, k)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_secretbox_keygen(call: FlutterMethodCall) -> Any
  {
    var k = [UInt8](repeating: 0, count: crypto_secretbox_keybytes())
    flutter_sodium.crypto_secretbox_keygen(&k)
    return FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_shorthash(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let i = (args["in"] as! FlutterStandardTypedData).uint8Array
    let key = (args["k"] as! FlutterStandardTypedData).uint8Array
    var out = [UInt8](repeating: 0, count: flutter_sodium.crypto_shorthash_bytes())

    let ret = flutter_sodium.crypto_shorthash(&out, i, CUnsignedLongLong(i.count), key)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(out))
  }

  private func crypto_shorthash_keygen(call: FlutterMethodCall) -> Any
  {
    var k = [UInt8](repeating: 0, count: flutter_sodium.crypto_shorthash_keybytes())
    flutter_sodium.crypto_shorthash_keygen(&k)
    return FlutterStandardTypedData.init(bytes: Data(k))
  }

  private func crypto_sign_seed_keypair(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let seed = (args["seed"] as! FlutterStandardTypedData).uint8Array

    var pk = [UInt8](repeating: 0, count: flutter_sodium.crypto_sign_publickeybytes())
    var sk = [UInt8](repeating: 0, count: flutter_sodium.crypto_sign_secretkeybytes())
    let ret = flutter_sodium.crypto_sign_seed_keypair(&pk, &sk, seed)
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: Data(pk)),
      "sk": FlutterStandardTypedData.init(bytes: Data(sk))
    ]
  }

  private func crypto_sign_keypair(call: FlutterMethodCall) -> Any
  {
    var pk = [UInt8](repeating: 0, count: flutter_sodium.crypto_sign_publickeybytes())
    var sk = [UInt8](repeating: 0, count: flutter_sodium.crypto_sign_secretkeybytes())
    let ret = flutter_sodium.crypto_sign_keypair(&pk, &sk)
    return error(ret: ret) ?? [
      "pk": FlutterStandardTypedData.init(bytes: Data(pk)),
      "sk": FlutterStandardTypedData.init(bytes: Data(sk))
    ]
  }

  private func crypto_sign(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var sm = [UInt8](repeating: 0, count: m.count + flutter_sodium.crypto_sign_bytes())
    let ret = flutter_sodium.crypto_sign(&sm, nil, m, CUnsignedLongLong(m.count), sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(sm))
  }

  private func crypto_sign_open(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let sm = (args["sm"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array

    var m = [UInt8](repeating: 0, count: sm.count - flutter_sodium.crypto_sign_bytes())
    let ret = flutter_sodium.crypto_sign_open(&m, nil, sm, CUnsignedLongLong(sm.count), pk)

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(m))
  }

  private func crypto_sign_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var sig = [UInt8](repeating: 0, count: flutter_sodium.crypto_sign_bytes())
    let ret = flutter_sodium.crypto_sign_detached(&sig, nil, m, CUnsignedLongLong(m.count), sk)

    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(sig))
  }

  private func crypto_sign_verify_detached(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let sig = (args["sig"] as! FlutterStandardTypedData).uint8Array
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array

    let ret = flutter_sodium.crypto_sign_verify_detached(sig, m, CUnsignedLongLong(m.count), pk)

    return ret == 0
  }

  private func crypto_sign_init(call: FlutterMethodCall) -> Any
  {
    var state = Data(count: crypto_sign_statebytes())
    let ret = state.asCryptoSignState { state in
      flutter_sodium.crypto_sign_init(&state)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: state)
  }

  private func crypto_sign_update(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    let m = (args["m"] as! FlutterStandardTypedData).uint8Array

    let ret = state.asCryptoSignState { state in
      flutter_sodium.crypto_sign_update(&state, m, CUnsignedLongLong(m.count))
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: state)
  }

  private func crypto_sign_final_create(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var sig = [UInt8](repeating: 0, count: crypto_sign_bytes())

    let ret = state.asCryptoSignState { state in
      flutter_sodium.crypto_sign_final_create(&state, &sig, nil, sk)
    }
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(sig))
  }

  private func crypto_sign_final_verify(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    var state = (args["state"] as! FlutterStandardTypedData).data
    var sig = (args["sig"] as! FlutterStandardTypedData).uint8Array
    let pk = (args["pk"] as! FlutterStandardTypedData).uint8Array

    let ret = state.asCryptoSignState { state in
      flutter_sodium.crypto_sign_final_verify(&state, &sig, pk)
    }
    return ret == 0
  }

  private func crypto_sign_ed25519_sk_to_curve25519(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let sk = (args["sk"] as! FlutterStandardTypedData).uint8Array

    var curve25519Sk = [UInt8](repeating: 0, count: flutter_sodium.crypto_scalarmult_curve25519_bytes())
    let ret = flutter_sodium.crypto_sign_ed25519_sk_to_curve25519(&curve25519Sk, sk)
    return error(ret: ret) ?? FlutterStandardTypedData.init(bytes: Data(curve25519Sk))
  }

  private func randombytes_buf(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let size = args["size"] as! Int

    var buf = [UInt8](repeating: 0, count: size)
    flutter_sodium.randombytes_buf(&buf, size)
    return FlutterStandardTypedData.init(bytes: Data(buf))
  }

  private func randombytes_buf_deterministic(call: FlutterMethodCall) -> Any
  {
    let args = call.arguments as! NSDictionary
    let size = args["size"] as! Int
    let seed = (args["seed"] as! FlutterStandardTypedData).uint8Array

    var buf = [UInt8](repeating: 0, count: size)
    flutter_sodium.randombytes_buf_deterministic(&buf, size, seed)
    return FlutterStandardTypedData.init(bytes: Data(buf))
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

  private func sodium_version_string(call: FlutterMethodCall) -> Any
  {
    return String(cString: flutter_sodium.sodium_version_string())
  }
}
