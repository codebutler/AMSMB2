//
//  main.swift
//  SMB2ServerExample
//
//  A simple SMB2 server that serves files from a local directory.
//

import Foundation
import AMSMB2

// Create a temporary directory to serve
let shareDir = "/tmp/smb2share"
try? FileManager.default.createDirectory(atPath: shareDir, withIntermediateDirectories: true)

// Create some test files
FileManager.default.createFile(atPath: "\(shareDir)/hello.txt", contents: "Hello from AMSMB2 Server!\n".data(using: .utf8))
FileManager.default.createFile(atPath: "\(shareDir)/test.txt", contents: "This is a test file.\n".data(using: .utf8))
try? FileManager.default.createDirectory(atPath: "\(shareDir)/subdir", withIntermediateDirectories: true)
FileManager.default.createFile(atPath: "\(shareDir)/subdir/nested.txt", contents: "Nested file content.\n".data(using: .utf8))

print("SMB2 Server Example")
print("===================")
print("Serving files from: \(shareDir)")
print("")

// Create the file system handler
let handler = SMB2FileSystemHandler(
    rootPath: shareDir,
    shareName: "share",
    users: [:]  // Empty means anonymous access
)

// Configure the server
let config = SMB2ServerConfiguration(
    port: 4450,  // Use non-privileged port for testing
    maxConnections: 10,
    hostname: "AMSMB2",
    domain: "WORKGROUP",
    signingEnabled: false,
    allowAnonymous: true
)

// Create and start the server
let server = SMB2Server(configuration: config, handler: handler)

print("Server starting on port \(config.port)...")
print("")
print("To test with smbclient:")
print("  smbclient //localhost/share -p \(config.port) -N")
print("")
print("Or mount:")
print("  mount -t cifs //localhost/share /mnt -o port=\(config.port),guest")
print("")
print("Press Ctrl+C to stop the server...")

// Start server - this blocks
do {
    try server.start()
} catch {
    print("Server stopped with error: \(error)")
    exit(1)
}
