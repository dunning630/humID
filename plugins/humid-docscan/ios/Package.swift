// swift-tools-version:5.9
import PackageDescription

let package = Package(
  name: "tauri-plugin-humid-docscan",
  platforms: [.iOS(.v17)], // the app itself needs iOS 26 (tauri.conf.json); the camera uses iOS 17+ APIs
  products: [
    .library(name: "tauri-plugin-humid-docscan", type: .static, targets: ["tauri-plugin-humid-docscan"])
  ],
  dependencies: [
    .package(name: "Tauri", path: "../.tauri/tauri-api")
  ],
  targets: [
    .target(
      name: "tauri-plugin-humid-docscan",
      dependencies: [.byName(name: "Tauri")],
      path: "Sources")
  ]
)
