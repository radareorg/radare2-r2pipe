// swift-tools-version:5.8

import PackageDescription

let package = Package(
    name: "r2pipe",
    products: [
        .library(name: "r2pipe", targets: ["R2Pipe"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "R2Pipe",
            path: "swift/Sources/r2pipe",
            swiftSettings: [
                .define("USE_SPAWN"),
            ]
        ),
        .testTarget(
            name: "R2PipeTests",
            dependencies: ["R2Pipe"],
            path: "swift/Tests/R2PipeTests"
        ),
    ]
)
