//
//  ServerVirtualFS.swift
//  AMSMB2
//
//  Created by Claude. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

// MARK: - Virtual File System

/// A virtual file entry
public class VirtualFile: @unchecked Sendable {
    public var name: String
    public var isDirectory: Bool
    public var data: Data
    public var creationTime: Date
    public var modificationTime: Date
    public var attributes: UInt32
    public var children: [String: VirtualFile]

    public init(
        name: String,
        isDirectory: Bool = false,
        data: Data = Data(),
        creationTime: Date = Date(),
        modificationTime: Date = Date(),
        attributes: UInt32 = 0
    ) {
        self.name = name
        self.isDirectory = isDirectory
        self.data = data
        self.creationTime = creationTime
        self.modificationTime = modificationTime
        self.attributes = attributes == 0 ? (isDirectory ? UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY) : UInt32(SMB2_FILE_ATTRIBUTE_NORMAL)) : attributes
        self.children = [:]
    }

    public var size: UInt64 {
        UInt64(data.count)
    }
}

/// A server request handler that serves a virtual in-memory file system
public final class SMB2VirtualFSHandler: SMB2ServerRequestHandler, @unchecked Sendable {
    /// The root of the virtual file system
    public let root: VirtualFile

    /// The share name
    public let shareName: String

    /// User credentials (username -> password)
    public var users: [String: String]

    private let lock = NSLock()
    private var openFiles: [SMB2FileId: OpenHandle] = [:]
    private var fileIdCounter: UInt64 = 1

    private struct OpenHandle {
        let file: VirtualFile
        let path: String
        var offset: UInt64 = 0
        var directoryEnumerated: Bool = false
    }

    /// Create a new virtual file system handler
    /// - Parameters:
    ///   - shareName: The SMB share name clients will connect to
    ///   - users: Dictionary of username to password for authentication
    public init(shareName: String = "share", users: [String: String] = [:]) {
        self.root = VirtualFile(name: "", isDirectory: true)
        self.shareName = shareName
        self.users = users
    }

    /// Add a file to the virtual file system
    /// - Parameters:
    ///   - path: Path like "/dir/file.txt"
    ///   - data: File contents
    public func addFile(path: String, data: Data) {
        let components = path.split(separator: "/").map(String.init)
        guard !components.isEmpty else { return }

        var current = root
        for (index, component) in components.enumerated() {
            if index == components.count - 1 {
                // Last component - create file
                let file = VirtualFile(name: component, isDirectory: false, data: data)
                current.children[component] = file
            } else {
                // Intermediate directory
                if let existing = current.children[component] {
                    current = existing
                } else {
                    let dir = VirtualFile(name: component, isDirectory: true)
                    current.children[component] = dir
                    current = dir
                }
            }
        }
    }

    /// Add a directory to the virtual file system
    /// - Parameter path: Path like "/dir/subdir"
    public func addDirectory(path: String) {
        let components = path.split(separator: "/").map(String.init)
        guard !components.isEmpty else { return }

        var current = root
        for component in components {
            if let existing = current.children[component] {
                current = existing
            } else {
                let dir = VirtualFile(name: component, isDirectory: true)
                current.children[component] = dir
                current = dir
            }
        }
    }

    private func findFile(at path: String) -> VirtualFile? {
        let cleaned = path.replacingOccurrences(of: "\\", with: "/")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        if cleaned.isEmpty {
            return root
        }

        let components = cleaned.split(separator: "/").map(String.init)
        var current = root

        for component in components {
            guard let child = current.children[component] else {
                return nil
            }
            current = child
        }

        return current
    }

    private func nextFileId() -> SMB2FileId {
        lock.lock()
        defer { lock.unlock() }
        let id = fileIdCounter
        fileIdCounter += 1
        return SMB2FileId(persistentId: id, volatileId: id)
    }

    // MARK: - SMB2ServerRequestHandler

    public func authorizeUser(
        context: SMB2ServerContext,
        user: String,
        domain: String,
        workstation: String
    ) -> SMB2ServerHandlerResult {
        if users.isEmpty {
            return .success
        }
        if let password = users[user] {
            context.setPassword(password)
            return .success
        }
        return .error(.init(rawValue: SMB2_STATUS_LOGON_FAILURE))
    }

    public func handleTreeConnect(
        context: SMB2ServerContext,
        request: SMB2TreeConnectRequest,
        reply: inout SMB2TreeConnectReply
    ) -> SMB2ServerHandlerResult {
        let path = request.path.replacingOccurrences(of: "\\", with: "/")
        let components = path.split(separator: "/").map(String.init)
        let requestedShare = components.last ?? ""

        guard requestedShare.lowercased() == shareName.lowercased() else {
            return .error(.init(rawValue: SMB2_STATUS_BAD_NETWORK_NAME))
        }

        reply = SMB2TreeConnectReply(
            shareType: .disk,
            shareFlags: 0,
            capabilities: 0,
            maximalAccess: 0x001F01FF
        )

        return .success
    }

    public func handleTreeDisconnect(
        context: SMB2ServerContext,
        treeId: UInt32
    ) -> SMB2ServerHandlerResult {
        return .success
    }

    public func handleCreate(
        context: SMB2ServerContext,
        request: SMB2CreateRequest,
        reply: inout SMB2CreateReply
    ) -> SMB2ServerHandlerResult {
        let path = request.name
        var file = findFile(at: path)

        // Handle create disposition
        switch request.createDisposition {
        case .open:
            guard file != nil else {
                return .error(.init(rawValue: SMB2_STATUS_OBJECT_NAME_NOT_FOUND))
            }
        case .create:
            guard file == nil else {
                return .error(.init(rawValue: SMB2_STATUS_OBJECT_NAME_COLLISION))
            }
            // Create will be handled by adding the file
            if request.isDirectory {
                addDirectory(path: path)
            } else {
                addFile(path: path, data: Data())
            }
            file = findFile(at: path)
        case .openIf:
            if file == nil {
                if request.isDirectory {
                    addDirectory(path: path)
                } else {
                    addFile(path: path, data: Data())
                }
                file = findFile(at: path)
            }
        case .overwrite, .overwriteIf, .supersede:
            if file == nil && request.createDisposition == .overwrite {
                return .error(.init(rawValue: SMB2_STATUS_OBJECT_NAME_NOT_FOUND))
            }
            if request.isDirectory {
                addDirectory(path: path)
            } else {
                addFile(path: path, data: Data())
            }
            file = findFile(at: path)
        }

        guard let file = file else {
            return .error(.init(rawValue: SMB2_STATUS_OBJECT_NAME_NOT_FOUND))
        }

        let fileId = nextFileId()

        lock.lock()
        openFiles[fileId] = OpenHandle(file: file, path: path)
        lock.unlock()

        reply = SMB2CreateReply(
            oplockLevel: 0,
            flags: 0,
            createAction: .opened,
            creationTime: file.creationTime,
            lastAccessTime: file.modificationTime,
            lastWriteTime: file.modificationTime,
            changeTime: file.modificationTime,
            allocationSize: (file.size + 4095) & ~4095,
            endOfFile: file.size,
            fileAttributes: file.attributes,
            fileId: fileId
        )

        return .success
    }

    public func handleClose(
        context: SMB2ServerContext,
        request: SMB2CloseRequest,
        reply: inout SMB2CloseReply
    ) -> SMB2ServerHandlerResult {
        lock.lock()
        if let handle = openFiles.removeValue(forKey: request.fileId) {
            reply = SMB2CloseReply(
                flags: request.flags,
                creationTime: handle.file.creationTime,
                lastAccessTime: handle.file.modificationTime,
                lastWriteTime: handle.file.modificationTime,
                changeTime: handle.file.modificationTime,
                allocationSize: (handle.file.size + 4095) & ~4095,
                endOfFile: handle.file.size,
                fileAttributes: handle.file.attributes
            )
        }
        lock.unlock()
        return .success
    }

    public func handleRead(
        context: SMB2ServerContext,
        request: SMB2ReadRequest,
        reply: inout SMB2ReadReply
    ) -> SMB2ServerHandlerResult {
        lock.lock()
        guard let handle = openFiles[request.fileId] else {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_FILE_CLOSED))
        }
        lock.unlock()

        let file = handle.file
        let offset = Int(request.offset)
        let length = Int(request.length)

        if offset >= file.data.count {
            reply = SMB2ReadReply(data: Data())
            return .success
        }

        let endIndex = min(offset + length, file.data.count)
        let data = file.data[offset..<endIndex]

        reply = SMB2ReadReply(data: Data(data))
        return .success
    }

    public func handleWrite(
        context: SMB2ServerContext,
        request: SMB2WriteRequest,
        reply: inout SMB2WriteReply
    ) -> SMB2ServerHandlerResult {
        lock.lock()
        guard let handle = openFiles[request.fileId] else {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_FILE_CLOSED))
        }
        lock.unlock()

        let file = handle.file
        let offset = Int(request.offset)
        let newData = request.data

        // Extend file if needed
        if offset + newData.count > file.data.count {
            file.data.append(Data(count: offset + newData.count - file.data.count))
        }

        // Write data
        file.data.replaceSubrange(offset..<(offset + newData.count), with: newData)
        file.modificationTime = Date()

        reply = SMB2WriteReply(count: UInt32(newData.count))
        return .success
    }

    public func handleQueryDirectory(
        context: SMB2ServerContext,
        request: SMB2QueryDirectoryRequest,
        reply: inout SMB2QueryDirectoryReply
    ) -> SMB2ServerHandlerResult {
        lock.lock()
        guard var handle = openFiles[request.fileId], handle.file.isDirectory else {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_FILE_CLOSED))
        }

        if handle.directoryEnumerated && (request.flags & UInt8(SMB2_RESTART_SCANS)) == 0 {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_NO_MORE_FILES))
        }

        handle.directoryEnumerated = true
        openFiles[request.fileId] = handle
        lock.unlock()

        var entries: [SMB2QueryDirectoryReply.DirectoryEntry] = []

        // Add . and ..
        entries.append(SMB2QueryDirectoryReply.DirectoryEntry(
            name: ".",
            creationTime: handle.file.creationTime,
            lastAccessTime: handle.file.modificationTime,
            lastWriteTime: handle.file.modificationTime,
            changeTime: handle.file.modificationTime,
            fileAttributes: UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
        ))
        entries.append(SMB2QueryDirectoryReply.DirectoryEntry(
            name: "..",
            creationTime: handle.file.creationTime,
            lastAccessTime: handle.file.modificationTime,
            lastWriteTime: handle.file.modificationTime,
            changeTime: handle.file.modificationTime,
            fileAttributes: UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
        ))

        // Add children
        for (name, child) in handle.file.children {
            entries.append(SMB2QueryDirectoryReply.DirectoryEntry(
                name: name,
                creationTime: child.creationTime,
                lastAccessTime: child.modificationTime,
                lastWriteTime: child.modificationTime,
                changeTime: child.modificationTime,
                endOfFile: child.size,
                allocationSize: (child.size + 4095) & ~4095,
                fileAttributes: child.attributes
            ))
        }

        reply = SMB2QueryDirectoryReply(entries: entries)
        return .success
    }

    public func handleQueryInfo(
        context: SMB2ServerContext,
        request: SMB2QueryInfoRequest,
        reply: inout SMB2QueryInfoReply
    ) -> SMB2ServerHandlerResult {
        lock.lock()
        guard let handle = openFiles[request.fileId] else {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_FILE_CLOSED))
        }
        lock.unlock()

        let file = handle.file

        switch request.infoType {
        case .file:
            reply.outputBuffer = buildFileInfo(
                infoClass: request.fileInfoClass,
                file: file
            )
        case .filesystem:
            reply.outputBuffer = buildFilesystemInfo(
                infoClass: request.fileInfoClass
            )
        default:
            return .error(.init(rawValue: SMB2_STATUS_NOT_SUPPORTED))
        }

        return .success
    }

    public func handleSetInfo(
        context: SMB2ServerContext,
        request: SMB2SetInfoRequest
    ) -> SMB2ServerHandlerResult {
        return .success
    }

    public func handleIoctl(
        context: SMB2ServerContext,
        request: SMB2IoctlRequest,
        reply: inout SMB2IoctlReply
    ) -> SMB2ServerHandlerResult {
        if request.ctlCode == SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO {
            return .success
        }
        return .error(.init(rawValue: SMB2_STATUS_NOT_SUPPORTED))
    }

    // MARK: - Helper Methods

    private func buildFileInfo(infoClass: UInt8, file: VirtualFile) -> Data {
        var data = Data()

        let creationTime = dateToWinTime(file.creationTime)
        let accessTime = dateToWinTime(file.modificationTime)
        let writeTime = dateToWinTime(file.modificationTime)
        let changeTime = dateToWinTime(file.modificationTime)
        let fileSize = file.size
        let allocationSize = (fileSize + 4095) & ~4095

        switch Int32(infoClass) {
        case SMB2_FILE_BASIC_INFORMATION:
            appendUInt64(&data, creationTime)
            appendUInt64(&data, accessTime)
            appendUInt64(&data, writeTime)
            appendUInt64(&data, changeTime)
            appendUInt32(&data, file.attributes)
            appendUInt32(&data, 0)  // Reserved

        case SMB2_FILE_STANDARD_INFORMATION:
            appendUInt64(&data, allocationSize)
            appendUInt64(&data, fileSize)
            appendUInt32(&data, 1)  // NumberOfLinks
            data.append(0)  // DeletePending
            data.append(file.isDirectory ? 1 : 0)  // Directory
            appendUInt16(&data, 0)  // Reserved

        case SMB2_FILE_ALL_INFORMATION:
            // Basic info
            appendUInt64(&data, creationTime)
            appendUInt64(&data, accessTime)
            appendUInt64(&data, writeTime)
            appendUInt64(&data, changeTime)
            appendUInt32(&data, file.attributes)
            appendUInt32(&data, 0)  // Reserved
            // Standard info
            appendUInt64(&data, allocationSize)
            appendUInt64(&data, fileSize)
            appendUInt32(&data, 1)  // NumberOfLinks
            data.append(0)  // DeletePending
            data.append(file.isDirectory ? 1 : 0)  // Directory
            appendUInt16(&data, 0)  // Reserved
            // Internal info
            appendUInt64(&data, 0)  // IndexNumber
            // EA info
            appendUInt32(&data, 0)  // EaSize
            // Access info
            appendUInt32(&data, 0x001F01FF)  // AccessFlags
            // Position info
            appendUInt64(&data, 0)  // CurrentByteOffset
            // Mode info
            appendUInt32(&data, 0)  // Mode
            // Alignment info
            appendUInt32(&data, 0)  // AlignmentRequirement
            // Name info
            appendUInt32(&data, 0)  // FileNameLength

        case SMB2_FILE_NETWORK_OPEN_INFORMATION:
            appendUInt64(&data, creationTime)
            appendUInt64(&data, accessTime)
            appendUInt64(&data, writeTime)
            appendUInt64(&data, changeTime)
            appendUInt64(&data, allocationSize)
            appendUInt64(&data, fileSize)
            appendUInt32(&data, file.attributes)
            appendUInt32(&data, 0)  // Reserved

        default:
            break
        }

        return data
    }

    private func buildFilesystemInfo(infoClass: UInt8) -> Data {
        var data = Data()

        switch Int32(infoClass) {
        case SMB2_FILE_FS_SIZE_INFORMATION:
            appendUInt64(&data, 1_000_000)  // TotalAllocationUnits
            appendUInt64(&data, 500_000)    // AvailableAllocationUnits
            appendUInt32(&data, 1)          // SectorsPerAllocationUnit
            appendUInt32(&data, 4096)       // BytesPerSector

        case SMB2_FILE_FS_ATTRIBUTE_INFORMATION:
            appendUInt32(&data, 0x00000003)  // FileSystemAttributes
            appendUInt32(&data, 255)         // MaximumComponentNameLength
            let fsName = "VirtualFS".data(using: .utf16LittleEndian) ?? Data()
            appendUInt32(&data, UInt32(fsName.count))
            data.append(fsName)

        case SMB2_FILE_FS_VOLUME_INFORMATION:
            appendUInt64(&data, 0)  // VolumeCreationTime
            appendUInt32(&data, 0x12345678)  // VolumeSerialNumber
            let volumeLabel = "VirtualFS".data(using: .utf16LittleEndian) ?? Data()
            appendUInt32(&data, UInt32(volumeLabel.count))
            data.append(0)  // SupportsObjects
            data.append(0)  // Reserved
            data.append(volumeLabel)

        case SMB2_FILE_FS_DEVICE_INFORMATION:
            appendUInt32(&data, UInt32(FILE_DEVICE_DISK))  // DeviceType
            appendUInt32(&data, 0)  // Characteristics

        case SMB2_FILE_FS_FULL_SIZE_INFORMATION:
            appendUInt64(&data, 1_000_000)  // TotalAllocationUnits
            appendUInt64(&data, 500_000)    // CallerAvailableAllocationUnits
            appendUInt64(&data, 500_000)    // ActualAvailableAllocationUnits
            appendUInt32(&data, 1)          // SectorsPerAllocationUnit
            appendUInt32(&data, 4096)       // BytesPerSector

        default:
            break
        }

        return data
    }

    private func dateToWinTime(_ date: Date) -> UInt64 {
        let windowsEpochOffset: TimeInterval = 11644473600
        let unixTime = date.timeIntervalSince1970
        let windowsTime = (unixTime + windowsEpochOffset) * 10_000_000
        return UInt64(windowsTime)
    }

    private func appendUInt64(_ data: inout Data, _ value: UInt64) {
        var v = value.littleEndian
        data.append(Data(bytes: &v, count: 8))
    }

    private func appendUInt32(_ data: inout Data, _ value: UInt32) {
        var v = value.littleEndian
        data.append(Data(bytes: &v, count: 4))
    }

    private func appendUInt16(_ data: inout Data, _ value: UInt16) {
        var v = value.littleEndian
        data.append(Data(bytes: &v, count: 2))
    }
}
