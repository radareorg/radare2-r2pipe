// swift-tools-version:5.8

import PackageDescription

let package = Package(
    name: "r2pipe",
    products: [
        .library(name: "r2pipe", targets: ["R2Pipe"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "R2Pipe")
    ]
)
