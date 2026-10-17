// iOS gate (humid-gate@2). Every check is a live Face ID / Touch ID match:
// the passcode is never offered and never accepted.
//
//   secret         32 random bytes in the Keychain, access control
//                  .biometryCurrentSet (deleted if faces or fingers change).
//   liveness key   P-256 key in the Secure Enclave, access control
//                  .privateKeyUsage + .biometryCurrentSet. It signs the
//                  request's challenge in the same check that reads the secret.
//   App Attest     when a device is added (`attest` sent), Apple's App Attest
//                  service vouches that this genuine HumID app made the
//                  liveness key: clientDataHash = SHA-256(attest ‖ key SPKI).
//
// One check per operation: LAContext evaluates .deviceOwnerAuthenticationWithBiometrics
// once (fallback button hidden), and that same context is handed to both the
// Keychain read and the Secure Enclave signature.
//
// Needs NSFaceIDUsageDescription (src-tauri/Info.ios.plist) and the
// com.apple.developer.devicecheck.appattest-environment entitlement.

import CryptoKit
import DeviceCheck
import Foundation
import LocalAuthentication
import Security
import Tauri
import UIKit
import WebKit

private let service = "app.humid.gate"
private let gateMethod = "ios-keychain-biometry"
/// DER prefix that turns a raw uncompressed P-256 point into SubjectPublicKeyInfo.
private let p256SpkiPrefix = Data([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
  0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
])

/// Holds a callback's result for the thread waiting on it (no captured-var mutation).
private final class Box<T> {
  var value: T
  init(_ value: T) { self.value = value }
}

class EnrollArgs: Decodable {
  var prompt: String?
  var challenge: String?
  var attest: String?
}

class HandleArg: Decodable {
  let id: String
}

class ReleaseArgs: Decodable {
  let handle: HandleArg
  var prompt: String?
  var challenge: String?
  var attest: String?
}

class ForgetArgs: Decodable {
  let handle: HandleArg
}

/// Arguments come from the WebView: checked here, never trusted.
private func b64ok(_ s: String?, _ max: Int) -> Bool {
  guard let s = s else { return true }
  return s.count <= max && s.range(of: "^[A-Za-z0-9+/_-]*={0,2}$", options: .regularExpression) != nil
}
private func badArgs(prompt: String?, challenge: String?, attest: String?, id: String? = nil) -> String? {
  if let p = prompt, p.count > 120 || p.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) { return "The prompt isn't valid." }
  if !b64ok(challenge, 8192) { return "The challenge isn't valid." }
  if !b64ok(attest, 128) { return "The attestation challenge isn't valid." }
  if !b64ok(id, 64) { return "The stored gate handle is malformed." }
  return nil
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

  /* ---------- screen exposure ----------
   * The app switcher's snapshot, screen recording and mirroring see a plain cover,
   * never the vault, codes or the camera. Third-party keyboards (which can log and
   * send what's typed) are refused: only Apple's keyboard types into HumID. */
  private var cover: UIView?
  private var observers: [NSObjectProtocol] = []
  private weak var web: WKWebView?

  override func load(webview: WKWebView) {
    super.load(webview: webview)
    web = webview
    let nc = NotificationCenter.default
    observers.append(nc.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in self?.setCovered(true) })
    observers.append(nc.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { [weak self] _ in self?.setCovered(true) })
    observers.append(nc.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in self?.setCovered(HumidGatePlugin.captured(self?.web)) })
    observers.append(nc.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in self?.setCovered(HumidGatePlugin.captured(self?.web)) })
    DispatchQueue.main.async { [weak self] in
      HumidGatePlugin.refuseThirdPartyKeyboards()
      self?.setCovered(HumidGatePlugin.captured(self?.web))
    }
  }

  private static func captured(_ webview: WKWebView?) -> Bool {
    return webview?.window?.windowScene?.screen.isCaptured ?? UIScreen.main.isCaptured
  }

  private func setCovered(_ on: Bool) {
    guard let window = web?.window else { return }
    if on {
      if cover != nil { return }
      let v = UIView(frame: window.bounds)
      v.backgroundColor = UIColor(red: 0.024, green: 0.082, blue: 0.043, alpha: 1)
      v.autoresizingMask = [.flexibleWidth, .flexibleHeight]
      window.addSubview(v)
      cover = v
    } else {
      cover?.removeFromSuperview()
      cover = nil
    }
  }

  private static var keyboardsRefused = false
  /** application(_:shouldAllowExtensionPointIdentifier:) → false for .keyboard, added to the app delegate. */
  private static func refuseThirdPartyKeyboards() {
    guard !keyboardsRefused, let delegate = UIApplication.shared.delegate else { return }
    keyboardsRefused = true
    let sel = #selector(UIApplicationDelegate.application(_:shouldAllowExtensionPointIdentifier:))
    let cls: AnyClass = type(of: delegate)
    if class_getInstanceMethod(cls, sel) != nil { return } // the app already decides
    let block: @convention(block) (AnyObject, UIApplication, UIApplication.ExtensionPointIdentifier) -> Bool = { _, _, id in id != .keyboard }
    guard class_addMethod(cls, sel, imp_implementationWithBlock(block), "B@:@@") else { return }
    // UIKit notes which optional methods its delegate has when it's set: set it again.
    UIApplication.shared.delegate = delegate
  }

  private func biometryLabel(_ ctx: LAContext) -> String {
    switch ctx.biometryType {
    case .faceID: return "Face ID"
    case .touchID: return "Touch ID"
    default: return "Face ID or Touch ID"
    }
  }

  @objc public func probe(_ invoke: Invoke) {
    let ctx = LAContext()
    var err: NSError?
    let ok = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    var out: [String: Any] = [
      "available": ok, "method": gateMethod, "assurance": "hardware", "label": biometryLabel(ctx),
      "modalities": ctx.biometryType == .faceID ? ["face"] : ["fingerprint"],
    ]
    if #available(iOS 14.0, *), DCAppAttestService.shared.isSupported { out["proof"] = "apple-app-attest" }
    if !ok {
      out["reason"] = "Face ID or Touch ID is not set up on this iPhone, or HumID is not allowed to use it. HumID never accepts the passcode instead."
    }
    invoke.resolve(out)
  }

  @objc public func enroll(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(EnrollArgs.self)
    if let bad = badArgs(prompt: args.prompt, challenge: args.challenge, attest: args.attest) { invoke.reject(bad); return }
    let id = Self.randomId()
    queue.async {
      do {
        var secret = Data(count: 32)
        let rc = secret.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard rc == errSecSuccess else { throw GateError.keychain(rc) }
        try Self.store(id: id, secret: secret)
        secret.resetBytes(in: 0..<secret.count)
        // Read it straight back so enrolment itself requires a live match.
        var out = try Self.check(
          id: id, prompt: args.prompt ?? "Bind HumID to your face or fingerprint",
          challenge: args.challenge, attest: args.attest)
        out["handle"] = ["id": id]
        invoke.resolve(out)
      } catch {
        Self.remove(id: id)
        invoke.reject(error.localizedDescription)
      }
    }
  }

  @objc public func release(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ReleaseArgs.self)
    if let bad = badArgs(prompt: args.prompt, challenge: args.challenge, attest: args.attest, id: args.handle.id) { invoke.reject(bad); return }
    queue.async {
      do {
        let out = try Self.check(
          id: args.handle.id, prompt: args.prompt ?? "Confirm it's you",
          challenge: args.challenge, attest: args.attest)
        invoke.resolve(out)
      } catch {
        invoke.reject(error.localizedDescription)
      }
    }
  }

  @objc public func forget(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ForgetArgs.self)
    if let bad = badArgs(prompt: nil, challenge: nil, attest: nil, id: args.handle.id) { invoke.reject(bad); return }
    Self.remove(id: args.handle.id)
    invoke.resolve()
  }

  // MARK: one live check

  /// Attest a new liveness key first if asked (no prompt needed), then one
  /// Face ID / Touch ID evaluation that both reads the secret and lets the
  /// Secure Enclave sign `challenge`.
  private static func check(id: String, prompt: String, challenge: String?, attest: String?) throws -> [String: Any] {
    let chal = try challenge.map(decode)
    var attestation: [String: Any]?
    if let att = try attest.map(decode) {
      let key = try createLiveKey(id: id)
      let spki = try spkiOf(key)
      if let object = try appAttest(clientDataHash: Data(SHA256.hash(data: att + spki))) {
        attestation = ["kind": "apple-app-attest", "object": object.base64EncodedString()]
      }
    }

    let ctx = try evaluate(prompt)
    defer { ctx.invalidate() }
    var secret = try read(id: id, ctx: ctx)
    defer { secret.resetBytes(in: 0..<secret.count) }

    var out: [String: Any] = [
      "secret": secret.base64EncodedString(),
      "method": gateMethod,
      "assurance": "hardware",
      "detail": ["factor": "biometric"],
    ]
    if let chal = chal, let key = loadLiveKey(id: id, ctx: ctx) {
      var live: [String: Any] = [
        "pub": try spkiOf(key).base64EncodedString(),
        "sig": try sign(key, chal).base64EncodedString(),
      ]
      if let a = attestation { live["attestation"] = a }
      out["live"] = live
    } else if attest != nil {
      throw GateError.unavailable("The Secure Enclave key could not be used.")
    }
    return out
  }

  private static func decode(_ s: String) throws -> Data {
    guard let d = Data(base64Encoded: s) else { throw GateError.unavailable("Malformed request from HumID.") }
    return d
  }

  /// One Face ID / Touch ID check. No passcode fallback: the button is hidden
  /// and the policy is biometrics-only, so a lockout is an error, not a passcode prompt.
  private static func evaluate(_ prompt: String) throws -> LAContext {
    let ctx = LAContext()                               // a fresh context for every check, never reused
    ctx.touchIDAuthenticationAllowableReuseDuration = 0 // no "unlocked a moment ago" reuse
    ctx.localizedFallbackTitle = ""
    ctx.localizedCancelTitle = "Cancel"
    var canErr: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &canErr) else {
      throw GateError.unavailable(laMessage(canErr.flatMap { LAError.Code(rawValue: $0.code) }))
    }
    let done = DispatchSemaphore(value: 0)
    let result = Box<(Bool, Error?)>((false, nil))
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: prompt) { success, error in
      result.value = (success, error)
      done.signal()
    }
    done.wait()
    guard result.value.0 else {
      let code = (result.value.1 as? LAError)?.code
      switch code {
      case .some(.userCancel), .some(.appCancel), .some(.systemCancel), .some(.userFallback):
        throw GateError.cancelled
      default:
        throw GateError.unavailable(laMessage(code))
      }
    }
    return ctx
  }

  private static func laMessage(_ code: LAError.Code?) -> String {
    switch code {
    case .some(.biometryLockout):
      return "Face ID or Touch ID is locked after too many tries. Lock and unlock your iPhone, then try again."
    case .some(.biometryNotEnrolled):
      return "Set up Face ID or Touch ID in Settings to use HumID."
    case .some(.passcodeNotSet):
      return "Set a device passcode and Face ID or Touch ID to use HumID."
    case .some(.authenticationFailed):
      return "Face ID or Touch ID did not match."
    default:
      return "Face ID or Touch ID is not available, or HumID is not allowed to use it."
    }
  }

  // MARK: Secure Enclave liveness key

  private static func liveTag(_ id: String) -> Data { Data("app.humid.gate.live.\(id)".utf8) }

  private static func createLiveKey(id: String) throws -> SecKey {
    deleteLiveKey(id: id)
    var cfErr: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &cfErr)
    else {
      throw GateError.unavailable("Could not create a biometric access policy.")
    }
    let attrs: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: liveTag(id),
        kSecAttrAccessControl as String: ac,
      ] as [String: Any],
    ]
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &cfErr) else {
      let why = cfErr?.takeRetainedValue().localizedDescription ?? "unknown error"
      throw GateError.unavailable("This iPhone could not make a Secure Enclave key: \(why)")
    }
    return key
  }

  /// The key, bound to an already-evaluated context so signing doesn't prompt again.
  private static func loadLiveKey(id: String, ctx: LAContext) -> SecKey? {
    let q: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: liveTag(id),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
      kSecUseAuthenticationContext as String: ctx,
    ]
    var out: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let ref = out else { return nil }
    return (ref as! SecKey)
  }

  private static func deleteLiveKey(id: String) {
    let q: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: liveTag(id),
    ]
    SecItemDelete(q as CFDictionary)
  }

  private static func spkiOf(_ key: SecKey) throws -> Data {
    var cfErr: Unmanaged<CFError>?
    guard let pub = SecKeyCopyPublicKey(key),
      let raw = SecKeyCopyExternalRepresentation(pub, &cfErr) as Data?, raw.count == 65
    else {
      throw GateError.unavailable("Could not read the Secure Enclave public key.")
    }
    return p256SpkiPrefix + raw
  }

  /// ECDSA P-256 / SHA-256, DER encoded (X9.62).
  private static func sign(_ key: SecKey, _ message: Data) throws -> Data {
    var cfErr: Unmanaged<CFError>?
    guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &cfErr) as Data? else {
      let err = cfErr?.takeRetainedValue()
      if let e = err, CFErrorGetCode(e) == Int(errSecUserCanceled) || CFErrorGetCode(e) == LAError.userCancel.rawValue {
        throw GateError.cancelled
      }
      throw GateError.unavailable("The Secure Enclave did not sign: \(err?.localizedDescription ?? "unknown error")")
    }
    return sig
  }

  // MARK: App Attest

  /// nil when App Attest isn't available (simulator, some older devices):
  /// the server then refuses the device unless its policy allows unproven ones.
  private static func appAttest(clientDataHash: Data) throws -> Data? {
    guard #available(iOS 14.0, *) else { return nil }
    let svc = DCAppAttestService.shared
    guard svc.isSupported else { return nil }
    let done = DispatchSemaphore(value: 0)
    let key = Box<(String?, Error?)>((nil, nil))
    svc.generateKey { k, e in
      key.value = (k, e)
      done.signal()
    }
    done.wait()
    guard let kid = key.value.0 else { throw attestError(key.value.1) }
    let object = Box<(Data?, Error?)>((nil, nil))
    svc.attestKey(kid, clientDataHash: clientDataHash) { o, e in
      object.value = (o, e)
      done.signal()
    }
    done.wait()
    guard let o = object.value.0 else { throw attestError(object.value.1) }
    return o
  }

  private static func attestError(_ e: Error?) -> GateError {
    if #available(iOS 14.0, *), let dc = e as? DCError, dc.code == .serverUnavailable {
      return .unavailable("Couldn't reach Apple to prove this is the genuine HumID app. Check your connection and try again.")
    }
    return .unavailable("Apple couldn't vouch for this app (App Attest): \(e?.localizedDescription ?? "unknown error")")
  }

  // MARK: keychain secret

  private static func randomId() -> String {
    var b = Data(count: 16)
    _ = b.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
    return b.base64EncodedString()
  }

  private static func secretQuery(_ id: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: id,
    ]
  }

  private static func remove(id: String) {
    SecItemDelete(secretQuery(id) as CFDictionary)
    deleteLiveKey(id: id)
  }

  private static func store(id: String, secret: Data) throws {
    var cfErr: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &cfErr)
    else {
      throw GateError.unavailable("Could not create a biometric access policy.")
    }
    var q = secretQuery(id)
    SecItemDelete(q as CFDictionary)
    q[kSecValueData as String] = secret
    q[kSecAttrAccessControl as String] = ac
    let status = SecItemAdd(q as CFDictionary, nil)
    guard status == errSecSuccess else {
      if status == errSecNotAvailable || status == errSecInteractionNotAllowed {
        throw GateError.unavailable("Set a device passcode and Face ID or Touch ID to use HumID.")
      }
      throw GateError.keychain(status)
    }
  }

  private static func read(id: String, ctx: LAContext) throws -> Data {
    var q = secretQuery(id)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    q[kSecUseAuthenticationContext as String] = ctx
    var out: AnyObject?
    let status = SecItemCopyMatching(q as CFDictionary, &out)
    switch status {
    case errSecSuccess:
      guard let data = out as? Data, data.count == 32 else { throw GateError.invalidated }
      return data
    case errSecUserCanceled: throw GateError.cancelled
    case errSecItemNotFound: throw GateError.invalidated
    case errSecAuthFailed: throw GateError.unavailable("Face ID or Touch ID did not match.")
    default: throw GateError.keychain(status)
    }
  }
}

@_cdecl("init_plugin_humid_gate")
func initPlugin() -> Plugin {
  return HumidGatePlugin()
}
