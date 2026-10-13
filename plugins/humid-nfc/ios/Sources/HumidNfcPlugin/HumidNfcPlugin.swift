// iOS chip reader (humid-nfc@1). Core NFC's tag reader session finds a
// passport or ID card chip (ISO 14443, ISO 7816 application A0000002471001,
// listed in Info.plist) and this plugin passes APDUs to and from it. All
// ICAO 9303 logic (BAC / PACE, secure messaging, files, Active
// Authentication) runs in the shared @humid/emrtd module.
//
// Needs the "Near Field Communication Tag Reading" capability on the App ID,
// the com.apple.developer.nfc.readersession.formats entitlement (TAG) and an
// NFCReaderUsageDescription. iPhone 7 or later.

import CoreNFC
import Foundation
import Tauri

class BeginArgs: Decodable {
  var prompt: String?
  var timeoutMs: Int?
  var reader: String?
}

class TransceiveArgs: Decodable {
  let session: String
  let apdu: String
}

class MessageArgs: Decodable {
  let session: String
  let message: String
}

class EndArgs: Decodable {
  let session: String
  var message: String?
  var error: String?
}

class HumidNfcPlugin: Plugin, NFCTagReaderSessionDelegate {
  private var reader: NFCTagReaderSession?
  private var tag: NFCISO7816Tag?
  private var sessionId: String?
  private var waiting: Invoke?

  private static let unavailable = "This iPhone can't read ID chips. NFC chip reading needs an iPhone 7 or later."

  @objc public func probe(_ invoke: Invoke) {
    let ok = NFCTagReaderSession.readingAvailable
    var out: [String: Any] = ["available": ok, "kind": ok ? "phone" : "none", "readers": [String]()]
    if !ok { out["reason"] = Self.unavailable }
    invoke.resolve(out)
  }

  @objc public func begin(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(BeginArgs.self)
    guard NFCTagReaderSession.readingAvailable else { invoke.reject(Self.unavailable); return }
    DispatchQueue.main.async {
      self.waiting?.reject("Chip reading cancelled.")
      self.reader?.invalidate()
      self.tag = nil
      self.sessionId = nil
      self.waiting = invoke
      guard let s = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil) else {
        self.waiting = nil
        invoke.reject(Self.unavailable)
        return
      }
      s.alertMessage = args.prompt ?? "Hold the top of your iPhone flat against your passport's photo page, or against your ID card."
      self.reader = s
      s.begin()
    }
  }

  @objc public func transceive(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(TransceiveArgs.self)
    guard let tag = tag, args.session == sessionId else { invoke.reject("No chip reading session is open."); return }
    guard let data = Data(base64Encoded: args.apdu), let apdu = NFCISO7816APDU(data: data) else {
      invoke.reject("That command can't be sent to the chip.")
      return
    }
    tag.sendCommand(apdu: apdu) { response, sw1, sw2, error in
      if error != nil {
        invoke.reject("Lost contact with the chip. Hold the document still against the top of your iPhone and try again.")
        return
      }
      var out = response
      out.append(sw1)
      out.append(sw2)
      invoke.resolve(["response": out.base64EncodedString()])
    }
  }

  @objc public func message(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(MessageArgs.self)
    if args.session == sessionId { DispatchQueue.main.async { self.reader?.alertMessage = args.message } }
    invoke.resolve()
  }

  @objc public func end(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(EndArgs.self)
    DispatchQueue.main.async {
      if args.session == self.sessionId, let r = self.reader {
        if let e = args.error { r.invalidate(errorMessage: e) } else {
          r.alertMessage = args.message ?? "Done."
          r.invalidate()
        }
      }
      self.reader = nil
      self.tag = nil
      self.sessionId = nil
      invoke.resolve()
    }
  }

  // MARK: NFCTagReaderSessionDelegate

  func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

  func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
    let code = (error as? NFCReaderError)?.code
    let cancelled = code == .readerSessionInvalidationErrorUserCanceled || code == .readerSessionInvalidationErrorSessionTimeout
    if let w = waiting {
      w.reject(cancelled ? "Chip reading cancelled." : error.localizedDescription)
      waiting = nil
    }
    if session === reader {
      reader = nil
      tag = nil
      sessionId = nil
    }
  }

  func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
    guard let first = tags.first else { return }
    guard case let .iso7816(t) = first else {
      session.alertMessage = "That isn't a passport or ID card chip. Try again."
      session.restartPolling()
      return
    }
    session.connect(to: first) { error in
      if error != nil {
        session.alertMessage = "Couldn't connect. Hold the document still and try again."
        session.restartPolling()
        return
      }
      let id = UUID().uuidString
      self.tag = t
      self.sessionId = id
      session.alertMessage = "Reading the chip. Keep holding still…"
      self.waiting?.resolve(["session": id, "kind": "phone"])
      self.waiting = nil
    }
  }
}

@_cdecl("init_plugin_humid_nfc")
func initPlugin() -> Plugin {
  return HumidNfcPlugin()
}
