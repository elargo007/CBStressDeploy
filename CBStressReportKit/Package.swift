// swift-tools-version: 6.2
// 3-24-26 Created by SFP Sr
// The swift-tools-version declares the minimum version of Swift required to build this package.

// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "CBStressReportKit",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "CBStressReportKit",
            targets: ["CBStressReportKit"]
        )
    ],
    dependencies: [
        .package(path: "../CBStressCore")
    ],
    targets: [
        .target(
            name: "CBStressReportKit",
            dependencies: [
                "CBStressCore"
            ]
        ),
        .testTarget(
            name: "CBStressReportKitTests",
            dependencies: ["CBStressReportKit"]
        )
    ]
)
