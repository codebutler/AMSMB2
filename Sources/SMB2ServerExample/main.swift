//
//  main.swift
//  SMB2ServerExample
//
//  A simple SMB2 server that serves a virtual in-memory file system.
//

import Foundation
import AMSMB2

print("SMB2 Server Example")
print("===================")
print("")

// Create the virtual file system handler
let handler = SMB2VirtualFSHandler(
    shareName: "share",
    users: [:]  // Empty means anonymous access
)

// Add some test files
handler.addFile(path: "/hello.txt", data: "Hello from AMSMB2 Server!\n".data(using: .utf8)!)
handler.addFile(path: "/test.txt", data: "This is a test file.\n".data(using: .utf8)!)
handler.addDirectory(path: "/subdir")
handler.addFile(path: "/subdir/nested.txt", data: "Nested file content.\n".data(using: .utf8)!)

print("Virtual files created:")
print("  /hello.txt (26 bytes)")
print("  /test.txt (21 bytes)")
print("  /subdir/")
print("  /subdir/nested.txt (21 bytes)")
print("")

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
