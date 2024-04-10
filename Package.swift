// swift-tools-version:5.8

import PackageDescription

let package = Package(
    name: "r2pipe",
    products: [
        .library(name: "r2pipe", targets: ["r2pipeLibrary"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "r2pipeLibrary",
            path: "swift/Sources"
        )
    ]
)
