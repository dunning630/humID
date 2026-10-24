// swift-tools-version:5.3
import PackageDescription

let package = Package(
  name: "tauri-plugin-humid-gate",
  platforms: [.iOS("26.0")],
  products: [
    .library(name: "tauri-plugin-humid-gate", type: .static, targets: ["tauri-plugin-humid-gate"])
  ],
  dependencies: [
    .package(name: "Tauri", path: "../.tauri/tauri-api")
  ],
  targets: [
    .target(
      name: "tauri-plugin-humid-gate",
      dependencies: [.byName(name: "Tauri")],
      path: "Sources")
  ]
)
