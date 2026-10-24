// swift-tools-version:5.3
import PackageDescription

let package = Package(
  name: "tauri-plugin-humid-nfc",
  platforms: [.iOS("26.0")],
  products: [
    .library(name: "tauri-plugin-humid-nfc", type: .static, targets: ["tauri-plugin-humid-nfc"])
  ],
  dependencies: [
    .package(name: "Tauri", path: "../.tauri/tauri-api")
  ],
  targets: [
    .target(
      name: "tauri-plugin-humid-nfc",
      dependencies: [.byName(name: "Tauri")],
      path: "Sources")
  ]
)
