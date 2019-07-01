// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "Xisco",
    products: [
        .library(
            name: "Xisco",
            targets: ["Xisco"]),
    ],
    dependencies: [
        .package(url: "https://github.com/nixberg/Xoodyak", .branch("master")),
        .package(url: "https://github.com/nixberg/Ristretto255", .branch("master")),
    ],
    targets: [
        .target(
            name: "Xisco",
            dependencies: ["Xoodyak", "Ristretto255"]),
        .testTarget(
            name: "XiscoTests",
            dependencies: ["Xisco"]),
    ]
)
