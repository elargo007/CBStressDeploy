/// swift-tools-version:6.0
/// Package.swift created by SFP on 2-17-26
/// 2-18-26 Modify to fix error
/// 3-14-26 Modify to add Leaf to the dependencies and target products.

// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "CBStressWeb",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "CBStressWeb", targets: ["CBStressWeb"])
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),
        .package(url: "https://github.com/vapor/leaf.git", from: "4.4.0"),
        .package(path: "../CBStressCore"),
        .package(path: "../CBStressReportKit")
    ],
    targets: [
        .executableTarget(
            name: "CBStressWeb",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Leaf", package: "leaf"),
                "CBStressCore",
                "CBStressReportKit"
            ]
        ),
        .testTarget(
            name: "CBStressWebTests",
            dependencies: [
                .target(name: "CBStressWeb"),
                .product(name: "XCTVapor", package: "vapor")
            ]
        )
    ]
)
