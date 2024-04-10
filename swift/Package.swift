// swift-tools-version:5.10

import PackageDescription

let package = Package(
    name: "r2pipe",
    products: [
        .library(name: "r2pipe", targets: ["r2pipe"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "r2pipe")
    ]
)
