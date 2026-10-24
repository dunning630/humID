// iPhone document camera (humid-docscan@2, iOS 26+). AVFoundation under a transparent web view;
// the app's camera screen stays on top and draws the frame, the words and the buttons.
//
//   device     the virtual camera (triple, dual-wide or wide): close focus is possible
//   lens       cards and passport pages stay on the wide lens (switching only when HumID zooms):
//              too close means "Move back a little", never a 4× crop of the ultra-wide;
//              pages and photos may switch to macro by themselves
//   zoom       z = 1.25 × MFD(wide) / d_fill(1×): the document fills the frame from beyond the
//              wide lens's minimum focus distance (Apple's AVCamBarcode advice), 1…2.5
//   focus      continuous AF restricted to near range, the focus and exposure point on the
//              frame's centre, put back there when the subject area changes; a tap is a real
//              one-shot AF there, then back to the frame 2 s after it settles
//   AF state   isAdjustingFocus and lensPosition (KVO): "Focusing…" only while it really focuses
//   finding    Vision rectangles round the frame (document segmentation for pages and photos)
//   reading    PDF417 in the capture pipeline (AVCaptureMetadataOutput); the MRZ band with
//              Vision text, at most 3 a second while lined up; raw text to the app, which parses
//   still      zero-shutter-lag AVCapturePhotoOutput from the running session, cut out with
//              CIPerspectiveCorrection on the GPU, kept in memory until `take` hands it over once
//
// Nothing is written to disk or logged. It handles no keys.

import AVFoundation
import CoreImage
import CoreImage.CIFilterBuiltins
import ImageIO
import Tauri
import UIKit
import Vision
import WebKit

class RectArg: Decodable { var x: Double = 0; var y: Double = 0; var w: Double = 0; var h: Double = 0 }
class SizeArg: Decodable { var w: Double = 0; var h: Double = 0 }
class ReadArg: Decodable { var pdf417: Bool? = false; var mrz: Bool? = false; var require: Bool? = false }
class OpenArgs: Decodable {
  let shape: String
  let read: ReadArg
  let frame: RectArg
  let view: SizeArg
  let auto: Bool
  let haptics: Bool
  let events: Channel
}
class FrameArgs: Decodable { let frame: RectArg; let view: SizeArg }
class PointArgs: Decodable { let x: Double; let y: Double }
class TorchArgs: Decodable { let on: Bool }
class TakeArgs: Decodable { let id: String; let which: String }

private let ratios: [String: Double] = ["id1": 85.6 / 54, "td3": 125.0 / 88, "page": 1.35]
private let widthMm: [String: Double] = ["id1": 85.6, "td3": 125, "page": 216]
private let outLong: [String: CGFloat] = ["id1": 1600, "td3": 2000, "page": 2600, "full": 2600]

/// A still in memory until `take` hands it over.
private final class Still {
  let id: String
  var doc: CIImage?
  var full: CIImage?
  init(id: String, doc: CIImage?, full: CIImage?) { self.id = id; self.doc = doc; self.full = full }
}

/// Where things are: the analysis buffer and the still (0…1, sensor orientation, y down; both are the same
/// zoomed view) ↔ the preview layer's points (the buffer turned for the screen, then aspect-filled) ↔ CSS pixels.
private struct Geometry {
  var bufToLayer = CGAffineTransform.identity
  var cssPerLayer: CGFloat = 1
  var frameCss = CGRect.zero
  var frameBuf = CGRect(x: 0, y: 0, width: 1, height: 1)
  var viewCss = CGSize(width: 1, height: 1)
  func css(_ b: CGPoint) -> CGPoint { let l = b.applying(bufToLayer); return CGPoint(x: l.x * cssPerLayer, y: l.y * cssPerLayer) }
  func buf(_ c: CGPoint) -> CGPoint { CGPoint(x: c.x / cssPerLayer, y: c.y / cssPerLayer).applying(bufToLayer.inverted()) }
}

final class PreviewView: UIView {
  override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
  var preview: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
}

@available(iOS 17.0, *)
class HumidDocscanPlugin: Plugin, AVCaptureVideoDataOutputSampleBufferDelegate, AVCaptureMetadataOutputObjectsDelegate, AVCapturePhotoCaptureDelegate {
  private weak var web: WKWebView?
  private var previewView: PreviewView?
  private let session = AVCaptureSession()
  private let sessionQueue = DispatchQueue(label: "app.humid.docscan.session")
  private let videoQueue = DispatchQueue(label: "app.humid.docscan.video", qos: .userInitiated)
  private let videoOutput = AVCaptureVideoDataOutput()
  private let metaOutput = AVCaptureMetadataOutput()
  private let stillOutput = AVCapturePhotoOutput()
  private var device: AVCaptureDevice?
  private var rotation: AVCaptureDevice.RotationCoordinator?
  private var observers: [NSKeyValueObservation] = []
  private var notes: [NSObjectProtocol] = []
  private let ci = CIContext(options: [.cacheIntermediates: false])

  private var events: Channel?
  private var shape = "id1"
  private var readPdf = false, readMrz = false, requireCode = false
  private var auto = true, haptics = true
  private var configured = false, isOn = false, paused = false, busy = false

  // shared between the main thread (geometry), the video queue (analysis) and KVO
  private let lock = NSLock()
  private var geo = Geometry()
  private var adjusting = false
  private var lensPosition: Float = 1
  private var lens = "wide"
  private var zoom: Double = 1
  private var tapAt: (x: Double, y: Double)?
  private var tapStarted = false

  // the video queue's own
  private let guidance = Guidance()
  private var last: Look?
  private var lastSent = 0, lastLook = 0, lastMrz = 0
  private var smooth: [CGPoint]?
  private var history: [(Int, [CGPoint])] = []
  private var sharpness: [Double] = []
  private var alignedSince: Int?
  private var wasAligned = false
  private var codeRead = false
  private var pdf417: String?
  private var mrzLines: [String] = []
  private var lastQuadDevice: [CGPoint]?
  private var still: Still?

  private let impact = UIImpactFeedbackGenerator(style: .light)
  private let notify = UINotificationFeedbackGenerator()

  private func ms() -> Int { Int(CACurrentMediaTime() * 1000) }
  @discardableResult private func locked<T>(_ f: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return f() }

  override func load(webview: WKWebView) {
    super.load(webview: webview)
    web = webview
    let nc = NotificationCenter.default
    notes.append(nc.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
      guard let self = self, self.isOn else { return }
      self.sessionQueue.async { self.session.stopRunning() }
    })
    notes.append(nc.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
      guard let self = self, self.isOn, !self.paused else { return }
      self.sessionQueue.async { if !self.session.isRunning { self.session.startRunning() } }
    })
    notes.append(nc.addObserver(forName: .AVCaptureSessionWasInterrupted, object: session, queue: .main) { [weak self] n in
      let code: Int = (n.userInfo?[AVCaptureSessionInterruptionReasonKey] as? NSNumber)?.intValue ?? -1
      let why: String = code >= 0 ? String(code) : "unknown"
      self?.send(["t": "interrupted", "reason": why])
    })
    notes.append(nc.addObserver(forName: .AVCaptureDeviceSubjectAreaDidChange, object: nil, queue: .main) { [weak self] _ in
      guard let self = self, self.tapAt == nil else { return }
      self.aimAtFrame()
    })
  }

  /* ---------------- commands ---------------- */

  @objc public func probe(_ invoke: Invoke) {
    let d = Self.pickDevice()
    var lenses: [String] = []
    if let d = d {
      let parts = d.isVirtualDevice ? d.constituentDevices : [d]
      for c in parts {
        switch c.deviceType {
        case .builtInUltraWideCamera: lenses.append("ultra")
        case .builtInTelephotoCamera: lenses.append("tele")
        default: lenses.append("wide")
        }
      }
    }
    var out: JsonObject = ["available": d != nil, "lenses": lenses, "macro": lenses.contains("ultra"), "torch": d?.hasTorch ?? false]
    if let mfd = d.map(Self.wideMinFocus), mfd > 0 { out["minFocusMm"] = mfd }
    if d == nil { out["reason"] = "This iPhone has no back camera HumID can use." }
    invoke.resolve(out)
  }

  @objc public func `open`(_ invoke: Invoke) {
    let a: OpenArgs
    do { a = try invoke.parseArgs(OpenArgs.self) } catch { invoke.reject("invalid: \(error.localizedDescription)"); return }
    guard ["id1", "td3", "page", "full"].contains(a.shape) else { invoke.reject("invalid: shape"); return }
    shape = a.shape; readPdf = a.read.pdf417 ?? false; readMrz = a.read.mrz ?? false; requireCode = a.read.require ?? false
    auto = a.auto; haptics = a.haptics; events = a.events
    let go = { DispatchQueue.main.async { self.start(a, invoke) } }
    switch AVCaptureDevice.authorizationStatus(for: .video) {
    case .authorized: go()
    case .notDetermined: AVCaptureDevice.requestAccess(for: .video) { ok in ok ? go() : invoke.reject("denied: camera access is off for HumID") }
    default: invoke.reject("denied: camera access is off for HumID")
    }
  }

  @objc public func frame(_ invoke: Invoke) {
    guard let a = try? invoke.parseArgs(FrameArgs.self) else { invoke.reject("invalid: frame"); return }
    DispatchQueue.main.async {
      self.updateGeometry(frame: a.frame, view: a.view)
      self.aimAtFrame()
      invoke.resolve()
    }
  }

  @objc public func focus(_ invoke: Invoke) {
    guard let a = try? invoke.parseArgs(PointArgs.self) else { invoke.reject("invalid: point"); return }
    DispatchQueue.main.async {
      guard let d = self.device, let pv = self.previewView, d.isFocusPointOfInterestSupported, d.isFocusModeSupported(.autoFocus) else {
        invoke.reject("unavailable: this camera can't focus on a point"); return
      }
      let g = self.locked { self.geo }
      let layerPt = CGPoint(x: a.x / Double(g.cssPerLayer), y: a.y / Double(g.cssPerLayer))
      let p = pv.preview.captureDevicePointConverted(fromLayerPoint: layerPt)
      do {
        try d.lockForConfiguration()
        d.focusPointOfInterest = p
        d.focusMode = .autoFocus
        if d.isExposurePointOfInterestSupported { d.exposurePointOfInterest = p; d.exposureMode = .autoExpose }
        d.unlockForConfiguration()
      } catch { invoke.reject("failed: \(error.localizedDescription)"); return }
      self.locked { self.tapAt = (a.x, a.y); self.tapStarted = false }
      invoke.resolve()
      // already in focus there: the lens never moves, so say so after a moment
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) {
        let untouched = self.locked { self.tapAt != nil && !self.tapStarted && !self.adjusting }
        if untouched { self.tapSettled() }
      }
    }
  }

  @objc public func torch(_ invoke: Invoke) {
    guard let a = try? invoke.parseArgs(TorchArgs.self) else { invoke.reject("invalid: torch"); return }
    sessionQueue.async {
      guard let d = self.device, d.hasTorch else { invoke.reject("unavailable: no light"); return }
      do {
        try d.lockForConfiguration()
        if a.on { try d.setTorchModeOn(level: AVCaptureDevice.maxAvailableTorchLevel) } else { d.torchMode = .off }
        d.unlockForConfiguration()
        invoke.resolve(["on": a.on])
      } catch { invoke.reject("failed: \(error.localizedDescription)") }
    }
  }

  @objc public func capture(_ invoke: Invoke) {
    videoQueue.async { self.shoot(how: "shutter", invoke: invoke) }
  }

  @objc public func take(_ invoke: Invoke) {
    guard let a = try? invoke.parseArgs(TakeArgs.self) else { invoke.reject("invalid: take"); return }
    videoQueue.async {
      guard let s = self.still, s.id == a.id else { invoke.reject("invalid: that photo is gone"); return }
      let img: CIImage?
      if a.which == "full" { img = s.full; s.full = nil } else { img = s.doc; s.doc = nil }
      if s.doc == nil && s.full == nil { self.still = nil }
      guard let im = img, let data = self.jpeg(im, quality: 0.92) else { invoke.reject("invalid: that photo is gone"); return }
      invoke.resolve(["data": data.base64EncodedString()])
    }
  }

  @objc public func pause(_ invoke: Invoke) {
    paused = true
    sessionQueue.async { self.session.stopRunning(); invoke.resolve() }
  }

  @objc public func resume(_ invoke: Invoke) {
    paused = false
    videoQueue.async {
      self.busy = false
      self.guidance.reset(); self.last = nil; self.smooth = nil; self.history = []; self.sharpness = []
      self.alignedSince = nil; self.wasAligned = false; self.codeRead = false; self.pdf417 = nil; self.mrzLines = []; self.still = nil
    }
    sessionQueue.async { if self.isOn && !self.session.isRunning { self.session.startRunning() }; invoke.resolve() }
    DispatchQueue.main.async { self.aimAtFrame() }
  }

  @objc public func close(_ invoke: Invoke) {
    DispatchQueue.main.async { self.stop(); invoke.resolve() }
  }

  /* ---------------- the camera ---------------- */

  private static func pickDevice() -> AVCaptureDevice? {
    AVCaptureDevice.DiscoverySession(deviceTypes: [.builtInTripleCamera, .builtInDualWideCamera, .builtInWideAngleCamera], mediaType: .video, position: .back).devices.first
  }

  /// The wide lens's own minimum focus distance (mm): a virtual device may report the ultra-wide's.
  private static func wideMinFocus(_ d: AVCaptureDevice) -> Int {
    let wide = d.constituentDevices.first { $0.deviceType == .builtInWideAngleCamera }
    return (wide ?? d).minimumFocusDistance
  }

  /// The zoom factor at which a virtual device is on its wide lens (1 on a single camera).
  private static func wideBase(_ d: AVCaptureDevice) -> CGFloat {
    guard d.isVirtualDevice, d.constituentDevices.first?.deviceType == .builtInUltraWideCamera,
          let f = d.virtualDeviceSwitchOverVideoZoomFactors.first else { return 1 }
    return CGFloat(truncating: f)
  }

  private func start(_ a: OpenArgs, _ invoke: Invoke) {
    guard let wv = web, let parent = wv.superview else { invoke.reject("failed: no web view"); return }
    guard let d = Self.pickDevice() else { invoke.reject("nocamera: no back camera"); return }
    stop()
    device = d
    let pv = PreviewView(frame: wv.frame)
    pv.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    pv.preview.videoGravity = .resizeAspectFill
    pv.preview.session = session
    pv.isAccessibilityElement = false
    parent.insertSubview(pv, belowSubview: wv)
    previewView = pv
    wv.isOpaque = false
    wv.backgroundColor = .clear
    wv.scrollView.backgroundColor = .clear
    isOn = true; paused = false; busy = false
    impact.prepare()
    sessionQueue.async {
      do {
        try self.configure(d)
        let pdf = self.readPdf && self.metaOutput.availableMetadataObjectTypes.contains(.pdf417)
        self.metaOutput.metadataObjectTypes = pdf ? [.pdf417] : []
        self.session.startRunning()
      } catch {
        DispatchQueue.main.async { self.stop() }
        invoke.reject("failed: \(error.localizedDescription)")
        return
      }
      DispatchQueue.main.async {
        self.rotation = AVCaptureDevice.RotationCoordinator(device: d, previewLayer: pv.preview)
        self.applyRotation()
        if let rc = self.rotation {
          self.observers.append(rc.observe(\.videoRotationAngleForHorizonLevelPreview, options: [.new]) { [weak self] _, _ in DispatchQueue.main.async { self?.applyRotation() } })
        }
        self.updateGeometry(frame: a.frame, view: a.view)
        self.setZoomAndLens()
        self.aimAtFrame()
        invoke.resolve(["session": UUID().uuidString])
        let z = self.locked { self.zoom }
        var ready: JsonObject = ["t": "ready", "lens": "wide", "zoom": z, "torch": d.hasTorch]
        let mfd = Self.wideMinFocus(d)
        if mfd > 0 { ready["minFocusMm"] = mfd }
        self.send(ready)
      }
    }
  }

  private func configure(_ d: AVCaptureDevice) throws {
    session.beginConfiguration()
    defer { session.commitConfiguration() }
    if !configured {
      session.sessionPreset = .photo
      for i in session.inputs { session.removeInput(i) }
      let input = try AVCaptureDeviceInput(device: d)
      guard session.canAddInput(input) else { throw NSError(domain: "humid", code: 1, userInfo: [NSLocalizedDescriptionKey: "the camera can't be used"]) }
      session.addInput(input)
      // frames for the guidance: preview-sized, late ones dropped, on one serial queue
      videoOutput.alwaysDiscardsLateVideoFrames = true
      videoOutput.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange]
      videoOutput.setSampleBufferDelegate(self, queue: videoQueue)
      if session.canAddOutput(videoOutput) { session.addOutput(videoOutput) }
      // the PDF417, read inside the pipeline
      if session.canAddOutput(metaOutput) { session.addOutput(metaOutput) }
      metaOutput.setMetadataObjectsDelegate(self, queue: videoQueue)
      // the still: added before the session runs (WebKit's lazy add reconfigured it at the shutter)
      if session.canAddOutput(stillOutput) { session.addOutput(stillOutput) }
      configured = true
    } else if let input = session.inputs.first as? AVCaptureDeviceInput, input.device != d {
      session.removeInput(input)
      let n = try AVCaptureDeviceInput(device: d)
      if session.canAddInput(n) { session.addInput(n) }
    }
    // a binned 4:3 format (lower power), 30 fps, with a ~12 MP still
    try d.lockForConfiguration()
    if let f = Self.pickFormat(d) {
      d.activeFormat = f
      d.activeVideoMinFrameDuration = CMTime(value: 1, timescale: 30)
      d.activeVideoMaxFrameDuration = CMTime(value: 1, timescale: 30)
    }
    if d.isLowLightBoostSupported { d.automaticallyEnablesLowLightBoostWhenAvailable = true }
    d.isSubjectAreaChangeMonitoringEnabled = true
    d.unlockForConfiguration()
    let dims = d.activeFormat.supportedMaxPhotoDimensions.filter { Int($0.width) * Int($0.height) <= 12_600_000 }
      .max { Int($0.width) * Int($0.height) < Int($1.width) * Int($1.height) }
    if let dims = dims { stillOutput.maxPhotoDimensions = dims }
    stillOutput.maxPhotoQualityPrioritization = .balanced
    if stillOutput.isZeroShutterLagSupported { stillOutput.isZeroShutterLagEnabled = true }
    if stillOutput.isResponsiveCaptureSupported { stillOutput.isResponsiveCaptureEnabled = true }
    // sensor-native buffers for the analysis and the still: Vision's and the device's coordinates then agree
    for out in [videoOutput as AVCaptureOutput, stillOutput] {
      if let c = out.connection(with: .video), c.isVideoRotationAngleSupported(0) { c.videoRotationAngle = 0 }
    }
    observe(d)
  }

  private static func pickFormat(_ d: AVCaptureDevice) -> AVCaptureDevice.Format? {
    let ok = d.formats.filter { f in
      let dims = CMVideoFormatDescriptionGetDimensions(f.formatDescription)
      return f.isVideoBinned && dims.width == 1920 && (dims.height == 1440 || dims.height == 1080)
        && f.videoSupportedFrameRateRanges.contains { $0.maxFrameRate >= 30 }
        && f.supportedMaxPhotoDimensions.contains { Int($0.width) * Int($0.height) >= 11_000_000 }
    }
    return ok.first { CMVideoFormatDescriptionGetDimensions($0.formatDescription).height == 1440 } ?? ok.first
  }

  /// The camera's own focus state, for the guidance and the tap ring.
  private func observe(_ d: AVCaptureDevice) {
    observers.removeAll()
    observers.append(d.observe(\.isAdjustingFocus, options: [.new]) { [weak self] dev, _ in
      guard let self = self else { return }
      let now = dev.isAdjustingFocus
      let settled: Bool = self.locked {
        self.adjusting = now
        if now && self.tapAt != nil { self.tapStarted = true }
        return !now && self.tapAt != nil && self.tapStarted
      }
      if settled { DispatchQueue.main.async { self.tapSettled() } }
    })
    observers.append(d.observe(\.lensPosition, options: [.new]) { [weak self] dev, _ in
      let p = dev.lensPosition
      self?.locked { self?.lensPosition = p }
    })
    if d.isVirtualDevice {
      observers.append(d.observe(\.activePrimaryConstituent, options: [.new]) { [weak self] dev, _ in
        let t = dev.activePrimaryConstituent?.deviceType
        let name = t == .builtInUltraWideCamera ? "ultra" : t == .builtInTelephotoCamera ? "tele" : "wide"
        self?.locked { self?.lens = name }
      })
    }
  }

  /// A tap's one-shot focus has settled: say so (the ring turns mint), then back to the frame 2 s later.
  private func tapSettled() {
    guard let t = locked({ tapAt }) else { return }
    locked { tapAt = nil; tapStarted = false }
    send(["t": "focus", "x": t.x, "y": t.y, "af": "focused"])
    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
      guard let self = self, self.locked({ self.tapAt == nil }) else { return }
      self.aimAtFrame()
    }
  }

  private func applyRotation() {
    guard let rc = rotation, let c = previewView?.preview.connection else { return }
    let angle = rc.videoRotationAngleForHorizonLevelPreview
    if c.isVideoRotationAngleSupported(angle) { c.videoRotationAngle = angle }
    recomputeGeometry()
  }

  /// The frame (CSS pixels) and the web view's size, and from them where the frame is in the camera's own coordinates.
  private func updateGeometry(frame: RectArg, view: SizeArg) {
    locked {
      geo.frameCss = CGRect(x: frame.x, y: frame.y, width: frame.w, height: frame.h)
      geo.viewCss = CGSize(width: max(1, view.w), height: max(1, view.h))
    }
    recomputeGeometry()
    updateRegions()
  }

  /// The buffer (sensor-native, 0…1, y down) as the preview layer shows it: turned by the preview's rotation
  /// (clockwise), then aspect-filled into the layer. Zoom needs nothing: buffer and preview are the same zoomed view.
  private func recomputeGeometry() {
    guard let pv = previewView, let d = device else { return }
    let angle = Int((pv.preview.connection?.videoRotationAngle ?? 90).rounded()) % 360
    let dims = CMVideoFormatDescriptionGetDimensions(d.activeFormat.formatDescription)
    let sw = CGFloat(max(dims.width, dims.height)), sh = CGFloat(min(dims.width, dims.height))
    let turned = angle == 90 || angle == 270
    let bw = turned ? sh : sw, bh = turned ? sw : sh
    let size = pv.bounds.size
    let k = max(size.width / bw, size.height / bh)
    let ox = (size.width - bw * k) / 2, oy = (size.height - bh * k) / 2
    // (u, v) in the buffer → 0…1 in the turned picture
    let r: CGAffineTransform
    switch angle {
    case 90: r = CGAffineTransform(a: 0, b: 1, c: -1, d: 0, tx: 1, ty: 0)
    case 180: r = CGAffineTransform(a: -1, b: 0, c: 0, d: -1, tx: 1, ty: 1)
    case 270: r = CGAffineTransform(a: 0, b: -1, c: 1, d: 0, tx: 0, ty: 1)
    default: r = .identity
    }
    let t = r.concatenating(CGAffineTransform(scaleX: bw * k, y: bh * k)).concatenating(CGAffineTransform(translationX: ox, y: oy))
    locked {
      geo.bufToLayer = t
      geo.cssPerLayer = geo.viewCss.width / max(1, size.width)
      let f = geo.frameCss
      let corners = [CGPoint(x: f.minX, y: f.minY), CGPoint(x: f.maxX, y: f.minY), CGPoint(x: f.maxX, y: f.maxY), CGPoint(x: f.minX, y: f.maxY)].map { geo.buf($0) }
      let xs = corners.map { $0.x }, ys = corners.map { $0.y }
      geo.frameBuf = CGRect(x: xs.min()!, y: ys.min()!, width: xs.max()! - xs.min()!, height: ys.max()! - ys.min()!)
    }
  }

  /// The frame in the preview layer's points.
  private func frameLayer() -> CGRect {
    locked { CGRect(x: geo.frameCss.minX / geo.cssPerLayer, y: geo.frameCss.minY / geo.cssPerLayer, width: geo.frameCss.width / geo.cssPerLayer, height: geo.frameCss.height / geo.cssPerLayer) }
  }

  /// The barcode reader looks only round the frame (the layer's own conversion, on the main thread).
  private func updateRegions() {
    guard let pv = previewView else { return }
    let all = CGRect(x: 0, y: 0, width: 1, height: 1)
    let r = shape == "full" ? all : pv.preview.metadataOutputRectConverted(fromLayerRect: frameLayer().insetBy(dx: -24, dy: -24)).intersection(all)
    sessionQueue.async { if !r.isNull, !r.isEmpty { self.metaOutput.rectOfInterest = r } }
  }

  /// Zoom so the document fills the frame from beyond the wide lens's minimum focus distance; cards stay on the wide lens.
  private func setZoomAndLens() {
    guard let d = device else { return }
    let base = Self.wideBase(d)
    var z: Double = 1
    let g = locked { geo }
    let mfd = Double(Self.wideMinFocus(d))
    if shape == "id1" || shape == "td3", mfd > 0, let doc = widthMm[shape], g.frameCss.width > 0 {
      // the field of view across the screen at 1× on the wide lens
      let fovLong = Double(d.activeFormat.videoFieldOfView) * .pi / 180
      let tanLongWide = tan(fovLong / 2) / Double(base)
      let dims = CMVideoFormatDescriptionGetDimensions(d.activeFormat.formatDescription)
      let short = Double(min(dims.width, dims.height)) / Double(max(dims.width, dims.height))
      // which sensor axis runs across the screen, and how much of it the aspect-filled layer shows
      let a = g.buf(CGPoint(x: 0, y: g.viewCss.height / 2)), b = g.buf(CGPoint(x: g.viewCss.width, y: g.viewCss.height / 2))
      let dx = abs(Double(b.x - a.x)), dy = abs(Double(b.y - a.y))
      let tanAcross = dx >= dy ? tanLongWide * dx : tanLongWide * short * dy
      let frac = Double(g.frameCss.width / g.viewCss.width)
      let dFill = doc / 2 / (tanAcross * frac)
      z = min(2.5, max(1, 1.25 * mfd / dFill))
    }
    do {
      try d.lockForConfiguration()
      let factor = min(d.maxAvailableVideoZoomFactor, max(d.minAvailableVideoZoomFactor, base * CGFloat(z)))
      d.videoZoomFactor = factor
      if d.activePrimaryConstituentDeviceSwitchingBehavior != .unsupported {
        if shape == "id1" || shape == "td3" {
          // only HumID's zoom may change the lens: no switch to the ultra-wide's macro when the card comes close
          d.setPrimaryConstituentDeviceSwitchingBehavior(.restricted, restrictedSwitchingBehaviorConditions: [.videoZoomChanged])
        } else {
          d.setPrimaryConstituentDeviceSwitchingBehavior(.auto, restrictedSwitchingBehaviorConditions: [])
        }
      }
      d.unlockForConfiguration()
      locked { zoom = (z * 100).rounded() / 100 }
    } catch { /* the default zoom */ }
  }

  /// Continuous AF and AE on the frame's centre, near range for cards and passport pages.
  private func aimAtFrame() {
    guard let d = device, let pv = previewView, isOn else { return }
    let f = shape == "full" ? pv.bounds : frameLayer()
    let c = pv.preview.captureDevicePointConverted(fromLayerPoint: CGPoint(x: f.midX, y: f.midY))
    do {
      try d.lockForConfiguration()
      if d.isFocusPointOfInterestSupported { d.focusPointOfInterest = c }
      if d.isFocusModeSupported(.continuousAutoFocus) { d.focusMode = .continuousAutoFocus }
      if d.isAutoFocusRangeRestrictionSupported { d.autoFocusRangeRestriction = (shape == "id1" || shape == "td3") ? .near : .none }
      if d.isSmoothAutoFocusSupported { d.isSmoothAutoFocusEnabled = false }
      if d.isExposurePointOfInterestSupported { d.exposurePointOfInterest = c }
      if d.isExposureModeSupported(.continuousAutoExposure) { d.exposureMode = .continuousAutoExposure }
      d.isSubjectAreaChangeMonitoringEnabled = true
      d.unlockForConfiguration()
    } catch { /* the camera's own default */ }
  }

  private func stop() {
    isOn = false; paused = false; busy = false
    observers.removeAll()
    rotation = nil
    sessionQueue.async {
      self.session.stopRunning()
      if let d = self.device, d.hasTorch, (try? d.lockForConfiguration()) != nil { d.torchMode = .off; d.unlockForConfiguration() }
    }
    previewView?.removeFromSuperview()
    previewView = nil
    if let wv = web { wv.isOpaque = true; wv.backgroundColor = .black; wv.scrollView.backgroundColor = .black }
    videoQueue.async {
      self.guidance.reset(); self.last = nil; self.smooth = nil; self.history = []; self.sharpness = []
      self.alignedSince = nil; self.wasAligned = false; self.codeRead = false; self.pdf417 = nil; self.mrzLines = []; self.still = nil
    }
  }

  /* ---------------- each frame (video queue) ---------------- */

  func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
    guard isOn, !paused, !busy, let px = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
    let now = ms()
    if now - lastLook < 70 { return } // about 12 looks a second
    lastLook = now
    let g = locked { geo }
    let full = shape == "full"
    // find the document round the frame (Vision: rectangles of the document's proportions; a page or anything: document segmentation)
    let roiDevice = full ? CGRect(x: 0, y: 0, width: 1, height: 1) : g.frameBuf.insetBy(dx: -g.frameBuf.width * 0.3, dy: -g.frameBuf.height * 0.3).intersection(CGRect(x: 0, y: 0, width: 1, height: 1))
    let quadDevice = findQuad(px, roiDevice: roiDevice)
    var quadCss: [CGPoint]? = nil
    var fit: String? = nil
    var light = "ok"
    var steady: Bool? = nil
    var sharp: Bool? = nil
    if let qd = quadDevice {
      let q = Self.screenOrder(qd.map { g.css($0) })
      // smoothed, so the corners glide (a big jump snaps)
      if let s = smooth, Self.moved(s, q) < 0.08 { quadCss = zip(s, q).map { CGPoint(x: $0.x * 0.5 + $1.x * 0.5, y: $0.y * 0.5 + $1.y * 0.5) } } else { quadCss = q }
      smooth = quadCss
      lastQuadDevice = quadCss!.map { g.buf($0) }
      if full {
        let a = Self.area(quadCss!) / Double(g.viewCss.width * g.viewCss.height)
        fit = a < 0.12 ? "far" : nil
      } else {
        fit = fitOf(quadCss!, g.frameCss, shape == "page" ? nil : ratios[shape])
      }
      // steady: the corners moved less than 1.5% of the document over 300 ms
      history.append((now, quadCss!))
      history.removeAll { now - $0.0 > 600 }
      let old = history.first(where: { now - $0.0 >= 240 }) ?? history[0]
      steady = Self.moved(old.1, quadCss!) < 0.015
      let stats = yStats(px, quadDevice: lastQuadDevice!)
      light = stats.light
      if let v = stats.lap {
        sharpness.append(v); if sharpness.count > 8 { sharpness.removeFirst() }
        if sharpness.count >= 3 { sharp = v >= (sharpness.max() ?? v) * 0.45 }
      }
    } else {
      smooth = nil; history = []; sharpness = []; lastQuadDevice = nil
      if yDark(px) { light = "dark" }
    }
    let aligned = quadDevice != nil && fit == nil
    if aligned { if alignedSince == nil { alignedSince = now } } else { alignedSince = nil }
    let (adj, lensPos, lensName) = locked { (adjusting, lensPosition, lens) }
    let focus: String? = adj ? "scanning" : "focused"
    // the lens at its near limit on the wide: too close to focus
    let near = !adj && lensPos <= 0.02 && lensName == "wide" && (shape == "id1" || shape == "td3")
    let wait = requireCode && !codeRead && (alignedSince.map { now - $0 < Rules.codeWaitMs } ?? true)
    let m = Measure(found: quadDevice != nil, quad: quadCss, fit: fit, light: light, focus: focus, near: near, sharp: sharp, steady: steady, wrong: nil, wait: wait)
    let look = guidance.feed(m, now)
    if look.aligned && !wasAligned { haptic { $0.impact.impactOccurred() } }
    wasAligned = look.aligned
    if (changed(last, look) && now - lastSent >= 100) || look.fire {
      last = look; lastSent = now
      send(lookJson(look, lens: lensName))
    }
    // the MRZ band, read while lined up and in focus (at most 3 a second)
    if readMrz && aligned && !adj && now - lastMrz >= 333, let q = lastQuadDevice {
      lastMrz = now
      readMrzBand(px, quadDevice: q)
    }
    if look.fire && auto { shoot(how: "auto", invoke: nil) }
  }

  private func lookJson(_ l: Look, lens: String) -> JsonObject {
    var o: JsonObject = ["t": "look", "state": l.state, "aligned": l.aligned, "steady": l.steady, "light": l.light, "progress": l.progress, "lens": lens]
    o["key"] = l.key.map { $0 as Any } ?? NSNull()
    o["focus"] = l.focus.map { $0 as Any } ?? NSNull()
    o["quad"] = l.quad.map { q in q.map { [Double($0.x), Double($0.y)] } as Any } ?? NSNull()
    return o
  }

  /// The document's corners in capture-device points, or nil.
  private func findQuad(_ px: CVPixelBuffer, roiDevice: CGRect) -> [CGPoint]? {
    let handler = VNImageRequestHandler(cvPixelBuffer: px, orientation: .up, options: [:])
    let roi = CGRect(x: roiDevice.minX, y: 1 - roiDevice.maxY, width: roiDevice.width, height: roiDevice.height)
    let obs: VNRectangleObservation?
    if shape == "id1" || shape == "td3" {
      let r = VNDetectRectanglesRequest()
      let want = Float(1 / (ratios[shape] ?? 1.585))
      r.minimumAspectRatio = want * 0.92
      r.maximumAspectRatio = min(1, want * 1.08)
      r.minimumSize = 0.3
      r.maximumObservations = 1
      r.minimumConfidence = 0.6
      r.quadratureTolerance = 20
      r.regionOfInterest = roi
      try? handler.perform([r])
      obs = r.results?.first
    } else {
      let r = VNDetectDocumentSegmentationRequest()
      r.regionOfInterest = roi
      try? handler.perform([r])
      obs = r.results?.first
    }
    guard let o = obs else { return nil }
    // Vision: normalised to the region, origin bottom left → capture-device points, origin top left
    func dev(_ p: CGPoint) -> CGPoint { CGPoint(x: roi.minX + p.x * roi.width, y: 1 - (roi.minY + p.y * roi.height)) }
    return [dev(o.topLeft), dev(o.topRight), dev(o.bottomRight), dev(o.bottomLeft)]
  }

  /// Corners as the person sees them: top left first, clockwise on screen.
  private static func screenOrder(_ q: [CGPoint]) -> [CGPoint] {
    let c = CGPoint(x: q.map { $0.x }.reduce(0, +) / 4, y: q.map { $0.y }.reduce(0, +) / 4)
    let around = q.sorted { atan2($0.y - c.y, $0.x - c.x) < atan2($1.y - c.y, $1.x - c.x) } // clockwise with y down
    let first = around.indices.min { around[$0].x + around[$0].y < around[$1].x + around[$1].y } ?? 0
    return (0..<4).map { around[(first + $0) % 4] }
  }

  private static func moved(_ a: [CGPoint], _ b: [CGPoint]) -> Double {
    let diag = max(1, Double(hypot(b[0].x - b[2].x, b[0].y - b[2].y)))
    return zip(a, b).map { Double(hypot($0.x - $1.x, $0.y - $1.y)) }.max()! / diag
  }

  private static func area(_ q: [CGPoint]) -> Double {
    var s = 0.0
    for i in 0..<4 { let n = q[(i + 1) % 4]; s += Double(q[i].x * n.y - n.x * q[i].y) }
    return abs(s) / 2
  }

  /// Light (dark / glare) and a Laplacian sharpness inside the quad, on the Y plane (sampled, no copy).
  private func yStats(_ px: CVPixelBuffer, quadDevice q: [CGPoint]) -> (light: String, lap: Double?) {
    CVPixelBufferLockBaseAddress(px, .readOnly)
    defer { CVPixelBufferUnlockBaseAddress(px, .readOnly) }
    guard let base = CVPixelBufferGetBaseAddressOfPlane(px, 0) else { return ("ok", nil) }
    let w = CVPixelBufferGetWidthOfPlane(px, 0), h = CVPixelBufferGetHeightOfPlane(px, 0), stride = CVPixelBufferGetBytesPerRowOfPlane(px, 0)
    let y = base.assumingMemoryBound(to: UInt8.self)
    let xs = q.map { $0.x * CGFloat(w) }, ys = q.map { $0.y * CGFloat(h) }
    let bw = xs.max()! - xs.min()!, bh = ys.max()! - ys.min()!
    let x0 = max(1, Int(xs.min()! + bw * 0.1)), x1 = min(w - 2, Int(xs.max()! - bw * 0.1))
    let y0 = max(1, Int(ys.min()! + bh * 0.1)), y1 = min(h - 2, Int(ys.max()! - bh * 0.1))
    if x1 - x0 < 16 || y1 - y0 < 16 { return ("ok", nil) }
    let step = max(1, (x1 - x0) / 220)
    var hist = [Int](repeating: 0, count: 256)
    var cs = [Int](repeating: 0, count: 24), cn = [Int](repeating: 0, count: 24)
    var n = 0, sum = 0, sat = 0
    var l1 = 0.0, l2 = 0.0, ln = 0
    var yy = y0
    while yy < y1 {
      let cy = min(3, (yy - y0) * 4 / max(1, y1 - y0))
      var xx = x0
      while xx < x1 {
        let o = yy * stride + xx
        let v = Int(y[o])
        hist[v] += 1; sum += v; n += 1
        let c = cy * 6 + min(5, (xx - x0) * 6 / max(1, x1 - x0))
        cn[c] += 1
        if v >= 253 { sat += 1; cs[c] += 1 }
        let lap = Double(4 * v - Int(y[o - 1]) - Int(y[o + 1]) - Int(y[o - stride]) - Int(y[o + stride]))
        l1 += lap; l2 += lap * lap; ln += 1
        xx += step
      }
      yy += step
    }
    guard n > 0 else { return ("ok", nil) }
    func pct(_ q: Double) -> Int { var a = 0; for v in 0..<256 { a += hist[v]; if Double(a) >= Double(n) * q { return v } }; return 255 }
    let mean = Double(sum) / Double(n)
    let lap = l2 / Double(ln) - (l1 / Double(ln)) * (l1 / Double(ln))
    if pct(0.95) < 85 || mean < 30 { return ("dark", lap) }
    let patches = (0..<24).filter { cn[$0] > 0 && Double(cs[$0]) / Double(cn[$0]) >= 0.5 }.count
    let share = Double(sat) / Double(n), white = pct(0.5) >= 228
    let page = shape == "page" && share > 0.4
    if !page && patches >= (white ? 2 : 1) && share >= (white ? 0.1 : 0.025) { return ("glare", lap) }
    return ("ok", lap)
  }

  /// The whole view is dark (nothing found because there's nothing to see).
  private func yDark(_ px: CVPixelBuffer) -> Bool {
    CVPixelBufferLockBaseAddress(px, .readOnly)
    defer { CVPixelBufferUnlockBaseAddress(px, .readOnly) }
    guard let base = CVPixelBufferGetBaseAddressOfPlane(px, 0) else { return false }
    let w = CVPixelBufferGetWidthOfPlane(px, 0), h = CVPixelBufferGetHeightOfPlane(px, 0), stride = CVPixelBufferGetBytesPerRowOfPlane(px, 0)
    let y = base.assumingMemoryBound(to: UInt8.self)
    var hist = [Int](repeating: 0, count: 256)
    var sum = 0, n = 0
    for yy in Swift.stride(from: 0, to: h, by: 16) { for xx in Swift.stride(from: 0, to: w, by: 16) { let v = Int(y[yy * stride + xx]); hist[v] += 1; sum += v; n += 1 } }
    var a = 0, p95 = 0
    for v in 0..<256 { a += hist[v]; if Double(a) >= Double(n) * 0.95 { p95 = v; break } }
    return n > 0 && Double(sum) / Double(n) < 28 && p95 < 50
  }

  /// The lines of <<< at the foot of the document (TD3: the bottom 30%; a card's back: the bottom 45%), straightened and read.
  private func readMrzBand(_ px: CVPixelBuffer, quadDevice q: [CGPoint]) {
    let img = CIImage(cvPixelBuffer: px)
    let W = img.extent.width, H = img.extent.height
    let share: CGFloat = shape == "td3" ? 0.30 : 0.45
    func lerp(_ a: CGPoint, _ b: CGPoint, _ t: CGFloat) -> CGPoint { CGPoint(x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t) }
    let band = [lerp(q[0], q[3], 1 - share), lerp(q[1], q[2], 1 - share), q[2], q[3]]
    guard let cut = perspective(img, band.map { CGPoint(x: $0.x * W, y: (1 - $0.y) * H) }, size: CGSize(width: 1320, height: 1320 * share / CGFloat(ratios[shape] ?? 1.42))),
          let cg = ci.createCGImage(cut, from: cut.extent) else { return }
    let r = VNRecognizeTextRequest()
    r.recognitionLevel = .accurate
    r.usesLanguageCorrection = false
    r.recognitionLanguages = ["en-US"]
    try? VNImageRequestHandler(cgImage: cg, orientation: .up, options: [:]).perform([r])
    let lines = (r.results ?? []).compactMap { $0.topCandidates(1).first?.string }
      .map { $0.uppercased().replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "«", with: "<") }
      .filter { $0.count >= 28 && $0.allSatisfy { ($0 >= "A" && $0 <= "Z") || ($0 >= "0" && $0 <= "9") || $0 == "<" } }
    guard lines.count >= 2 else { return }
    if lines == mrzLines { codeRead = true }
    mrzLines = lines
    send(["t": "code", "kind": "mrz", "state": "read", "lines": lines])
  }

  /* ---------------- the PDF417, read in the pipeline ---------------- */

  func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
    guard isOn, !busy, !codeRead else { return }
    for o in metadataObjects {
      guard let code = o as? AVMetadataMachineReadableCodeObject, code.type == .pdf417, let text = code.stringValue, (20...4000).contains(text.count) else { continue }
      codeRead = true
      pdf417 = text
      send(["t": "code", "kind": "pdf417", "state": "read", "text": text])
      return
    }
  }

  /* ---------------- the still ---------------- */

  /// The photo, from the running session (zero shutter lag where offered). Not in focus: one AF on the frame first (500 ms at most).
  private func shoot(how: String, invoke: Invoke?) {
    guard isOn, !busy else { invoke?.reject("invalid: the camera isn't ready"); return }
    busy = true
    let fire = {
      let s = AVCapturePhotoSettings(format: [AVVideoCodecKey: AVVideoCodecType.jpeg])
      s.maxPhotoDimensions = self.stillOutput.maxPhotoDimensions
      s.photoQualityPrioritization = .balanced
      #if compiler(>=6.0)
      if #available(iOS 18.0, *), self.stillOutput.isShutterSoundSuppressionSupported { s.isShutterSoundSuppressionEnabled = true }
      #endif
      self.pendingShot = (how, invoke)
      self.stillOutput.capturePhoto(with: s, delegate: self)
    }
    if locked({ adjusting }) {
      DispatchQueue.main.async { self.aimAtFrame() }
      videoQueue.asyncAfter(deadline: .now() + 0.5) { fire() }
    } else { fire() }
  }

  private var pendingShot: (String, Invoke?)?

  func photoOutput(_ output: AVCapturePhotoOutput, didFinishProcessingPhoto photo: AVCapturePhoto, error: Error?) {
    videoQueue.async { self.developed(photo, error) }
  }

  private func developed(_ photo: AVCapturePhoto, _ error: Error?) {
    let (how, invoke) = pendingShot ?? ("shutter", nil)
    pendingShot = nil
    guard error == nil, let data = photo.fileDataRepresentation(), let raw = CIImage(data: data, options: [.applyOrientationProperty: false]) else {
      busy = false
      haptic { $0.notify.notificationOccurred(.error) }
      invoke?.reject("failed: \(error?.localizedDescription ?? "no photo")")
      send(["t": "error", "code": "failed", "message": "Couldn't take the photo. Try again.", "soft": true])
      return
    }
    // sensor-native, like the video buffer; the video may be the still's centre crop (16:9 against 4:3)
    let W = raw.extent.width, H = raw.extent.height
    let g = locked { geo }
    var av = W / max(1, H)
    if let d = device { let dims = CMVideoFormatDescriptionGetDimensions(d.activeFormat.formatDescription); av = CGFloat(max(dims.width, dims.height)) / CGFloat(max(1, min(dims.width, dims.height))) }
    let ap = W / max(1, H)
    let sx: CGFloat = av > ap ? 1 : av / ap, sy: CGFloat = av > ap ? ap / av : 1
    /// a buffer point (0…1, y down) → the still's own 0…1, y down
    func toPhoto(_ p: CGPoint) -> CGPoint { CGPoint(x: 0.5 + (p.x - 0.5) * sx, y: 0.5 + (p.y - 0.5) * sy) }
    func fromPhoto(_ p: CGPoint) -> CGPoint { CGPoint(x: 0.5 + (p.x - 0.5) / sx, y: 0.5 + (p.y - 0.5) / sy) }
    func toCI(_ b: CGPoint) -> CGPoint { let p = toPhoto(b); return CGPoint(x: p.x * W, y: (1 - p.y) * H) }
    // the document found again in the still, near where the live view had it; else the frame
    var cutFound = false
    var quadDevice = [CGPoint(x: g.frameBuf.minX, y: g.frameBuf.minY), CGPoint(x: g.frameBuf.maxX, y: g.frameBuf.minY), CGPoint(x: g.frameBuf.maxX, y: g.frameBuf.maxY), CGPoint(x: g.frameBuf.minX, y: g.frameBuf.maxY)]
    let fb = g.frameBuf
    let nearBuf = shape == "full" ? CGRect(x: 0, y: 0, width: 1, height: 1) : fb.insetBy(dx: -fb.width * 0.15, dy: -fb.height * 0.15)
    let a0 = toPhoto(CGPoint(x: nearBuf.minX, y: nearBuf.minY)), a1 = toPhoto(CGPoint(x: nearBuf.maxX, y: nearBuf.maxY))
    if let q = stillQuad(raw, near: CGRect(x: a0.x, y: a0.y, width: a1.x - a0.x, height: a1.y - a0.y)) {
      quadDevice = q.map(fromPhoto); cutFound = true
    }
    // order the corners as on screen, so the cut-out comes out the way the person held it
    let screen = Self.screenOrder(quadDevice.map { g.css($0) }).map { g.buf($0) }
    var doc: CIImage? = nil
    var fullUpright: CIImage? = nil
    if shape != "full" || cutFound {
      let long = outLong[shape] ?? 1600
      let size: CGSize
      if let r = ratios[shape], shape != "page" { size = CGSize(width: long, height: (long / CGFloat(r)).rounded()) }
      else {
        let w = Double(hypot(screen[0].x * W - screen[1].x * W, screen[0].y * H - screen[1].y * H)), h = Double(hypot(screen[0].x * W - screen[3].x * W, screen[0].y * H - screen[3].y * H))
        size = w >= h ? CGSize(width: long, height: (long * CGFloat(h / max(1, w))).rounded()) : CGSize(width: (long * CGFloat(w / max(1, h))).rounded(), height: long)
      }
      doc = perspective(raw, screen.map(toCI), size: size)
    }
    if shape == "full" || shape == "page" {
      // the whole picture, upright as on screen (the screen's corners of the sensor's whole view)
      let corners = [CGPoint(x: 0, y: 0), CGPoint(x: 1, y: 0), CGPoint(x: 1, y: 1), CGPoint(x: 0, y: 1)].map(fromPhoto)
      let all = Self.screenOrder(corners.map { g.css($0) }).map { g.buf($0) }
      let upright = Double(hypot(all[0].x * W - all[1].x * W, all[0].y * H - all[1].y * H)) < Double(hypot(all[0].x * W - all[3].x * W, all[0].y * H - all[3].y * H))
      let long = outLong["full"]!
      let size = upright ? CGSize(width: (long * min(W, H) / max(W, H)).rounded(), height: long) : CGSize(width: long, height: (long * min(W, H) / max(W, H)).rounded())
      fullUpright = perspective(raw, all.map(toCI), size: size)
      if doc == nil { doc = fullUpright; fullUpright = nil }
    }
    guard let d = doc else {
      busy = false
      invoke?.reject("failed: no photo")
      send(["t": "error", "code": "failed", "message": "Couldn't take the photo. Try again.", "soft": true])
      return
    }
    // the barcode again, from the still, if the pipeline didn't read it
    if readPdf && pdf417 == nil, let cg = ci.createCGImage(d, from: d.extent) {
      let r = VNDetectBarcodesRequest()
      r.symbologies = [.pdf417]
      try? VNImageRequestHandler(cgImage: cg, orientation: .up, options: [:]).perform([r])
      pdf417 = r.results?.compactMap { $0.payloadStringValue }.first
    }
    let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(24).lowercased()
    still = Still(id: String(id), doc: d, full: fullUpright)
    let k = 720 / max(d.extent.width, d.extent.height)
    let freeze = jpeg(d.transformed(by: CGAffineTransform(scaleX: k, y: k)), quality: 0.72)?.base64EncodedString()
    var codes: JsonObject = [:]
    if let p = pdf417 { codes["pdf417"] = p }
    if !mrzLines.isEmpty { codes["mrz"] = mrzLines }
    haptic { $0.notify.notificationOccurred(.success) }
    let w = Int(d.extent.width), h = Int(d.extent.height)
    invoke?.resolve(["id": String(id), "width": w, "height": h])
    let (z, lensName) = locked { (zoom, lens) }
    send(["t": "captured", "id": String(id), "how": how, "width": w, "height": h, "cut": cutFound, "freeze": freeze.map { $0 as Any } ?? NSNull(), "codes": codes,
          "quad": quadDevice.map { [Double(g.css($0).x), Double(g.css($0).y)] }, "af": "focused", "sharpness": sharpness.last ?? 0, "lens": lensName, "zoom": z])
  }

  /// The document's corners in a still (its own 0…1, y down), looked for again near `near` (the same units).
  private func stillQuad(_ img: CIImage, near: CGRect) -> [CGPoint]? {
    let k = 1024 / max(img.extent.width, img.extent.height)
    guard let cg = ci.createCGImage(img.transformed(by: CGAffineTransform(scaleX: k, y: k)), from: img.extent.applying(CGAffineTransform(scaleX: k, y: k))) else { return nil }
    let handler = VNImageRequestHandler(cgImage: cg, orientation: .up, options: [:])
    let roi = near.intersection(CGRect(x: 0, y: 0, width: 1, height: 1))
    let v = CGRect(x: roi.minX, y: 1 - roi.maxY, width: roi.width, height: roi.height)
    let obs: VNRectangleObservation?
    if shape == "id1" || shape == "td3" {
      let r = VNDetectRectanglesRequest()
      let want = Float(1 / (ratios[shape] ?? 1.585))
      r.minimumAspectRatio = want * 0.92; r.maximumAspectRatio = min(1, want * 1.08)
      r.minimumSize = 0.5; r.maximumObservations = 1; r.minimumConfidence = 0.6; r.quadratureTolerance = 20
      r.regionOfInterest = v
      try? handler.perform([r]); obs = r.results?.first
    } else {
      let r = VNDetectDocumentSegmentationRequest()
      r.regionOfInterest = v
      try? handler.perform([r]); obs = r.results?.first
    }
    guard let o = obs else { return nil }
    func dev(_ p: CGPoint) -> CGPoint { CGPoint(x: v.minX + p.x * v.width, y: 1 - (v.minY + p.y * v.height)) }
    return [dev(o.topLeft), dev(o.topRight), dev(o.bottomRight), dev(o.bottomLeft)]
  }

  /// The part of `img` inside the corners (CI pixels; tl, tr, br, bl as they should come out), straightened, at `size`.
  private func perspective(_ img: CIImage, _ q: [CGPoint], size: CGSize) -> CIImage? {
    let f = CIFilter.perspectiveCorrection()
    f.inputImage = img
    f.topLeft = q[0]; f.topRight = q[1]; f.bottomRight = q[2]; f.bottomLeft = q[3]
    guard let out = f.outputImage, out.extent.width > 1, out.extent.height > 1 else { return nil }
    let moved = out.transformed(by: CGAffineTransform(translationX: -out.extent.minX, y: -out.extent.minY))
    return moved.transformed(by: CGAffineTransform(scaleX: size.width / moved.extent.width, y: size.height / moved.extent.height))
  }

  private func jpeg(_ img: CIImage, quality: CGFloat) -> Data? {
    guard let cs = CGColorSpace(name: CGColorSpace.sRGB) else { return nil }
    let opts = [CIImageRepresentationOption(rawValue: kCGImageDestinationLossyCompressionQuality as String): quality]
    return ci.jpegRepresentation(of: img, colorSpace: cs, options: opts)
  }

  /* ---------------- plumbing ---------------- */

  private func send(_ o: JsonObject) {
    events?.send(o)
  }

  private func haptic(_ f: @escaping (HumidDocscanPlugin) -> Void) {
    guard haptics else { return }
    DispatchQueue.main.async { f(self) }
  }
}

@_cdecl("init_plugin_humid_docscan")
func initPlugin() -> Plugin {
  // HumID 5.0 runs on iOS 26; the build's deployment target may be lower. An older system gets a
  // plugin with no commands, which the app reads as "no native camera" (it uses the web view's).
  if #available(iOS 17.0, *) { return HumidDocscanPlugin() }
  return Plugin()
}
