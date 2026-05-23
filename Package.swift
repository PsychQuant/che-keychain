// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "che-keychain",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "CheKeychain",
            path: "Sources/CheKeychain"
        ),
        .testTarget(
            name: "CheKeychainTests",
            dependencies: ["CheKeychain"],
            path: "Tests/CheKeychainTests"
        )
    ]
)
