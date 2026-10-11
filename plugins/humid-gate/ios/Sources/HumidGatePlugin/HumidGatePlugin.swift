// iOS gate: a random 32-byte secret in the Keychain, protected by
// SecAccessControl .biometryCurrentSet and only accessible while a device
// passcode is set. iOS releases it only after a Face ID / Touch ID match
// (no passcode fallback), and deletes it if the enrolled faces or fingers
// change. Needs NSFaceIDUsageDescription (shell/src-tauri/Info.ios.plist).

import Foundation
import LocalAuthentication
import Security
import Tauri
import UIKit
import WebKit

private let service = "app.humid.gate"
private let method = "ios-keychain-biometry"

class EnrollArgs: Decodable {
  var prompt: String?
}

class HandleArg: Decodable {
  let id: String
}

class ReleaseArgs: Decodable {
  let handle: HandleArg
  var prompt: String?
}

class ForgetArgs: Decodable {
  let handle: HandleArg
}

enum GateError: Error, LocalizedError {
  case cancelled
  case invalidated
  case unavailable(String)
  case keychain(OSStatus)

  var errorDescription: String? {
    switch self {
    case .cancelled: return "Biometric check cancelled."
    case .invalidated:
      return "The device biometric key is gone or was invalidated by a biometric change. This identity can no longer be unlocked here."
    case .unavailable(let r): return r
    case .keychain(let s): return "Keychain error \(s)."
    }
  }
}

class HumidGatePlugin: Plugin {
  private let queue = DispatchQueue(label: "app.humid.gate", qos: .userInitiated)

  private func biometryLabel(_ ctx: LAContext) -> String {
    switch ctx.biometryType {
    case .faceID: return "Face ID"
    case .touchID: return "Touch ID"
    default: return "Device biometric"
    }
  }

  @objc public func probe(_ invoke: Invoke) {
    let ctx = LAContext()
    var err: NSError?
    let ok = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    var out: [String: Any] = [
      "available": ok, "method": method, "assurance": "hardware", "label": biometryLabel(ctx),
    ]
    if !ok {
      out["reason"] = "Face ID or Touch ID is not set up on this device, or HumID is not allowed to use it."
    }
    invoke.resolve(out)
  }

  @objc public func enroll(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(EnrollArgs.self)
    let id = Self.randomId()
    queue.async {
      do {
        var secret = Data(count: 32)
        let rc = secret.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard rc == errSecSuccess else { throw GateError.keychain(rc) }
        try Self.store(id: id, secret: secret)
        secret.resetBytes(in: 0..<secret.count)
        // Read it straight back so enrolment itself requires a biometric match.
        let released = try Self.read(id: id, prompt: args.prompt ?? "Bind your HumID identity to this device")
        invoke.resolve([
          "handle": ["id": id],
          "secret": released.base64EncodedString(),
          "method": method,
          "assurance": "hardware",
          "detail": ["factor": "biometric"],
        ])
      } catch {
        invoke.reject(error.localizedDescription)
      }
    }
  }

  @objc public func release(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ReleaseArgs.self)
    queue.async {
      do {
        let secret = try Self.read(id: args.handle.id, prompt: args.prompt ?? "Confirm it's you")
        invoke.resolve([
          "secret": secret.base64EncodedString(),
          "method": method,
          "assurance": "hardware",
          "detail": ["factor": "biometric"],
        ])
      } catch {
        invoke.reject(error.localizedDescription)
      }
    }
  }

  @objc public func forget(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ForgetArgs.self)
    let q: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: args.handle.id,
    ]
    SecItemDelete(q as CFDictionary)
    invoke.resolve()
  }

  // MARK: keychain

  private static func randomId() -> String {
    var b = Data(count: 16)
    _ = b.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
    return b.base64EncodedString()
  }

  private static func store(id: String, secret: Data) throws {
    var cfErr: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &cfErr)
    else {
      throw GateError.unavailable("Could not create a biometric access policy.")
    }
    let q: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: id,
      kSecValueData as String: secret,
      kSecAttrAccessControl as String: ac,
    ]
    SecItemDelete(q as CFDictionary)
    let status = SecItemAdd(q as CFDictionary, nil)
    guard status == errSecSuccess else {
      if status == errSecNotAvailable || status == errSecInteractionNotAllowed {
        throw GateError.unavailable("Set a device passcode and Face ID or Touch ID to use HumID.")
      }
      throw GateError.keychain(status)
    }
  }

  private static func read(id: String, prompt: String) throws -> Data {
    let ctx = LAContext()
    ctx.localizedReason = prompt
    ctx.localizedFallbackTitle = ""  // no passcode fallback button
    let q: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: id,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
      kSecUseAuthenticationContext as String: ctx,
    ]
    var out: AnyObject?
    let status = SecItemCopyMatching(q as CFDictionary, &out)
    switch status {
    case errSecSuccess:
      guard let data = out as? Data, data.count == 32 else { throw GateError.invalidated }
      return data
    case errSecUserCanceled: throw GateError.cancelled
    case errSecItemNotFound: throw GateError.invalidated
    case errSecAuthFailed: throw GateError.unavailable("Face ID / Touch ID did not match.")
    default: throw GateError.keychain(status)
    }
  }
}

@_cdecl("init_plugin_humid_gate")
func initPlugin() -> Plugin {
  return HumidGatePlugin()
}
