// The document camera's guidance: a line-by-line port of apps/mobile/src/core/lookstate.js
// (the one set of rules every HumID camera follows; tests/fixtures/guidance.json is the golden
// set the JS and the Android port are tested against). Plain Swift, no camera.

import CoreGraphics
import Foundation

enum Rules {
  static let sayMs: [String: Int] = ["dark": 600, "glare": 500, "hold": 450, "tooclose": 0, "showback": 1200, "showfront": 1200, "showpage": 1500]
  static let sayDefault = 350
  static let switchMs = 550
  static let focusingMs = 250
  static let tooCloseMs = 600
  static let holdMs = 300
  static let graceMs = 300
  static let codeWaitMs = 2500

  static let small = 0.78, snug = 0.88, big = 1.06, shift = 0.045, tiltDeg = 6.0, flat = 0.1, ratio = 0.14

  static func sayAfter(_ key: String) -> Int { sayMs[key] ?? sayDefault }
}

struct Measure {
  var found: Bool
  var quad: [CGPoint]? = nil
  var fit: String? = nil
  var light: String = "ok"
  /// "scanning" | "focused" | "failed" | nil
  var focus: String? = nil
  var near: Bool = false
  var sharp: Bool? = nil
  var steady: Bool? = nil
  var wrong: String? = nil
  var wait: Bool = false
}

struct Look: Equatable {
  var state: String
  var key: String?
  var aligned: Bool
  var quad: [CGPoint]?
  var focus: String?
  var steady: Bool
  var light: String
  var progress: Double
  var fire: Bool
}

/// How a found document sits in the frame: a guide key, or nil when it is lined up. quad: tl, tr, br, bl.
func fitOf(_ q: [CGPoint], _ frame: CGRect, _ ratio: Double?) -> String? {
  func d(_ a: CGPoint, _ b: CGPoint) -> Double { Double(hypot(a.x - b.x, a.y - b.y)) }
  let tl = q[0], tr = q[1], br = q[2], bl = q[3]
  let top = d(tl, tr), bottom = d(bl, br), left = d(tl, bl), right = d(tr, br)
  let across = (top + bottom) / 2, down = (left + right) / 2
  if !(across > 0 && down > 0) { return "shape" }
  if let r = ratio, abs(across / down / r - 1) > Rules.ratio { return "shape" }
  let scale = max(across / Double(frame.width), down / Double(frame.height))
  if scale < Rules.small { return "closer" }
  if scale < Rules.snug { return "fill" }
  if scale > Rules.big { return "back" }
  let cx = Double(tl.x + tr.x + br.x + bl.x) / 4, cy = Double(tl.y + tr.y + br.y + bl.y) / 4
  if abs(cx - Double(frame.midX)) / Double(frame.width) > Rules.shift || abs(cy - Double(frame.midY)) / Double(frame.height) > Rules.shift { return "shift" }
  let deg = (atan2(Double(tr.y - tl.y), Double(tr.x - tl.x)) + atan2(Double(br.y - bl.y), Double(br.x - bl.x))) / 2 * 180 / .pi
  if abs(deg) > Rules.tiltDeg { return "tilt" }
  if abs(top - bottom) / across > Rules.flat || abs(left - right) / down > Rules.flat { return "flat" }
  return nil
}

final class Guidance {
  private var shown: String?
  private var candKey: String?
  private var candSince = 0
  private var scanSince: Int?
  private var closeSince: Int?
  private var holdSince: Int?
  private var lastGood: Int?
  private var fired = false

  func feed(_ m: Measure, _ now: Int) -> Look {
    let found = m.found, light = m.light, focus = m.focus
    var state: String
    var raw: String? = nil
    var aligned = false, close = false
    if light == "dark" { state = found ? "aligning" : "searching"; raw = "dark" }
    else if !found { state = "searching" }
    else if let f = m.fit { state = "aligning"; raw = f }
    else if let w = m.wrong { state = "aligning"; raw = w }
    else {
      aligned = true
      state = "sharp"
      if focus == "scanning" {
        if scanSince == nil { scanSince = now }
        if now - scanSince! >= Rules.focusingMs { state = "focusing" }
      } else { scanSince = nil }
      close = m.near || focus == "failed"
      if close { if closeSince == nil { closeSince = now } } else { closeSince = nil }
      if let cs = closeSince, now - cs >= Rules.tooCloseMs { raw = "tooclose" }
      else if light == "glare" || light == "bright" { raw = light }
      else if m.steady == false || m.sharp == false { raw = state == "focusing" ? nil : "hold" }
    }
    if !aligned { scanSince = nil; closeSince = nil }
    let good = aligned && raw == nil && !close && !m.wait && focus != "scanning"
    if good { if holdSince == nil { holdSince = now }; lastGood = now }
    else if !found || (holdSince != nil && now - (lastGood ?? now) > Rules.graceMs) { holdSince = nil }
    var progress = 0.0
    if let hs = holdSince, good { progress = min(1, Double(now - hs) / Double(Rules.holdMs)) }
    var fire = false
    if good, let hs = holdSince, now - hs >= Rules.holdMs, !fired { fired = true; fire = true; state = "ready"; progress = 1 }
    else if fired && aligned { state = "ready"; progress = 1 }
    if raw == nil { shown = nil; candKey = nil }
    else if raw == shown { candKey = nil }
    else {
      if candKey != raw { candKey = raw; candSince = now }
      let wait = shown != nil ? max(Rules.switchMs, Rules.sayAfter(raw!)) : Rules.sayAfter(raw!)
      if now - candSince >= wait { shown = raw; candKey = nil }
    }
    return Look(state: state, key: shown, aligned: aligned, quad: found ? m.quad : nil, focus: focus, steady: m.steady != false, light: light, progress: progress, fire: fire)
  }

  func reset() { shown = nil; candKey = nil; scanSince = nil; closeSince = nil; holdSince = nil; lastGood = nil; fired = false }
}

/// Is `b` worth sending after `a`? (lookstate.js changed)
func changed(_ a: Look?, _ b: Look) -> Bool {
  guard let a = a else { return true }
  if a.state != b.state || a.key != b.key || a.focus != b.focus || a.light != b.light || a.steady != b.steady || a.aligned != b.aligned { return true }
  if (a.progress * 10).rounded() != (b.progress * 10).rounded() { return true }
  if (a.quad == nil) != (b.quad == nil) { return true }
  guard let aq = a.quad, let bq = b.quad else { return false }
  let size = max(1, Double(hypot(bq[0].x - bq[2].x, bq[0].y - bq[2].y)))
  return bq.indices.contains { Double(hypot(bq[$0].x - aq[$0].x, bq[$0].y - aq[$0].y)) > size * 0.01 }
}
