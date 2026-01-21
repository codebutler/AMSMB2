//
//  ServerFileSystem.swift
//  AMSMB2
//
//  Created by Claude. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

// MARK: - File System Server Handler

/// A server request handler that serves files from a local directory
public final class SMB2FileSystemHandler: SMB2ServerRequestHandler, @unchecked Sendable {
    /// The root directory to serve files from
    public let rootPath: String

    /// The share name
    public let shareName: String

    /// User credentials (username -> password)
    public var users: [String: String]

    private let lock = NSLock()
    private var openFiles: [SMB2FileId: OpenFile] = [:]
    private var fileIdCounter: UInt64 = 1

    private struct OpenFile {
        let path: String
        var handle: FileHandle?
        var isDirectory: Bool
        var offset: UInt64 = 0
        var directoryEnumerated: Bool = false
    }

    /// Create a new file system handler
    /// - Parameters:
    ///   - rootPath: The local directory path to serve
    ///   - shareName: The SMB share name clients will connect to
    ///   - users: Dictionary of username to password for authentication
    public init(rootPath: String, shareName: String = "share", users: [String: String] = [:]) {
        self.rootPath = (rootPath as NSString).standardizingPath
        self.shareName = shareName
        self.users = users
    }

    private func localPath(for smbPath: String) -> String {
        let cleaned = smbPath.replacingOccurrences(of: "\\", with: "/")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if cleaned.isEmpty {
            return rootPath
        }
        return (rootPath as NSString).appendingPathComponent(cleaned)
    }

    private func nextFileId() -> SMB2FileId {
        lock.lock()
        defer { lock.unlock() }
        let id = fileIdCounter
        fileIdCounter += 1
        return SMB2FileId(persistentId: id, volatileId: id)
    }

    private func fileAttributes(at path: String) throws -> [FileAttributeKey: Any] {
        try FileManager.default.attributesOfItem(atPath: path)
    }

    // MARK: - SMB2ServerRequestHandler

    public func authorizeUser(
        context: SMB2ServerContext,
        user: String,
        domain: String,
        workstation: String
    ) -> SMB2ServerHandlerResult {
        // If no users configured, allow anonymous
        if users.isEmpty {
            return .success
        }

        // Check if user exists and set password
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
        // Extract share name from path (format: \\server\share)
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
            maximalAccess: 0x001F01FF  // Full access
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
        let path = localPath(for: request.name)
        let fm = FileManager.default
        var isDir: ObjCBool = false

        // Check if file exists
        let exists = fm.fileExists(atPath: path, isDirectory: &isDir)

        // Handle create disposition
        switch request.createDisposition {
        case .open:
            guard exists else {
                return .error(.init(rawValue: SMB2_STATUS_OBJECT_NAME_NOT_FOUND))
            }
        case .create:
            guard !exists else {
                return .error(.init(rawValue: SMB2_STATUS_OBJECT_NAME_COLLISION))
            }
            // Create new file
            if request.isDirectory {
                do {
                    try fm.createDirectory(atPath: path, withIntermediateDirectories: false)
                } catch {
                    return .error(.init(rawValue: SMB2_STATUS_ACCESS_DENIED))
                }
            } else {
                fm.createFile(atPath: path, contents: nil)
            }
        case .openIf:
            if !exists {
                if request.isDirectory {
                    do {
                        try fm.createDirectory(atPath: path, withIntermediateDirectories: false)
                    } catch {
                        return .error(.init(rawValue: SMB2_STATUS_ACCESS_DENIED))
                    }
                } else {
                    fm.createFile(atPath: path, contents: nil)
                }
            }
        case .overwrite, .overwriteIf:
            if exists && !isDir.boolValue {
                // Truncate existing file
                fm.createFile(atPath: path, contents: nil)
            } else if !exists {
                if request.createDisposition == .overwrite {
                    return .error(.init(rawValue: SMB2_STATUS_OBJECT_NAME_NOT_FOUND))
                }
                fm.createFile(atPath: path, contents: nil)
            }
        case .supersede:
            if exists && !isDir.boolValue {
                try? fm.removeItem(atPath: path)
            }
            if request.isDirectory {
                try? fm.createDirectory(atPath: path, withIntermediateDirectories: false)
            } else {
                fm.createFile(atPath: path, contents: nil)
            }
        }

        // Get file attributes
        guard let attrs = try? fileAttributes(at: path) else {
            return .error(.init(rawValue: SMB2_STATUS_OBJECT_NAME_NOT_FOUND))
        }

        let fileId = nextFileId()
        let fileType = attrs[.type] as? FileAttributeType
        let isDirectory = fileType == .typeDirectory

        // Open file handle if it's a file (not directory)
        var fileHandle: FileHandle? = nil
        if !isDirectory {
            if request.desiredAccess & UInt32(SMB2_FILE_WRITE_DATA) != 0 ||
               request.desiredAccess & UInt32(SMB2_FILE_APPEND_DATA) != 0 {
                fileHandle = FileHandle(forUpdatingAtPath: path)
            } else {
                fileHandle = FileHandle(forReadingAtPath: path)
            }
        }

        // Store open file
        lock.lock()
        openFiles[fileId] = OpenFile(
            path: path,
            handle: fileHandle,
            isDirectory: isDirectory
        )
        lock.unlock()

        let creationDate = attrs[.creationDate] as? Date ?? Date()
        let modificationDate = attrs[.modificationDate] as? Date ?? Date()
        let fileSize = attrs[.size] as? UInt64 ?? 0

        var fileAttrs: UInt32 = 0
        if isDirectory {
            fileAttrs |= UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
        } else {
            fileAttrs |= UInt32(SMB2_FILE_ATTRIBUTE_NORMAL)
        }

        reply = SMB2CreateReply(
            oplockLevel: 0,
            flags: 0,
            createAction: exists ? .opened : .created,
            creationTime: creationDate,
            lastAccessTime: modificationDate,
            lastWriteTime: modificationDate,
            changeTime: modificationDate,
            allocationSize: (fileSize + 4095) & ~4095,  // Round up to 4K
            endOfFile: fileSize,
            fileAttributes: fileAttrs,
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
        if let openFile = openFiles.removeValue(forKey: request.fileId) {
            openFile.handle?.closeFile()

            // Get final attributes
            if let attrs = try? fileAttributes(at: openFile.path) {
                let creationDate = attrs[.creationDate] as? Date ?? Date()
                let modificationDate = attrs[.modificationDate] as? Date ?? Date()
                let fileSize = attrs[.size] as? UInt64 ?? 0
                let fileType = attrs[.type] as? FileAttributeType

                var fileAttrs: UInt32 = 0
                if fileType == .typeDirectory {
                    fileAttrs |= UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
                } else {
                    fileAttrs |= UInt32(SMB2_FILE_ATTRIBUTE_NORMAL)
                }

                reply = SMB2CloseReply(
                    flags: request.flags,
                    creationTime: creationDate,
                    lastAccessTime: modificationDate,
                    lastWriteTime: modificationDate,
                    changeTime: modificationDate,
                    allocationSize: (fileSize + 4095) & ~4095,
                    endOfFile: fileSize,
                    fileAttributes: fileAttrs
                )
            }
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
        guard let openFile = openFiles[request.fileId], let handle = openFile.handle else {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_FILE_CLOSED))
        }
        lock.unlock()

        do {
            try handle.seek(toOffset: request.offset)
            let data = handle.readData(ofLength: Int(request.length))
            reply = SMB2ReadReply(data: data)
            return .success
        } catch {
            return .error(.init(rawValue: SMB2_STATUS_ACCESS_DENIED))
        }
    }

    public func handleWrite(
        context: SMB2ServerContext,
        request: SMB2WriteRequest,
        reply: inout SMB2WriteReply
    ) -> SMB2ServerHandlerResult {
        lock.lock()
        guard let openFile = openFiles[request.fileId], let handle = openFile.handle else {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_FILE_CLOSED))
        }
        lock.unlock()

        do {
            try handle.seek(toOffset: request.offset)
            handle.write(request.data)
            reply = SMB2WriteReply(count: UInt32(request.data.count))
            return .success
        } catch {
            return .error(.init(rawValue: SMB2_STATUS_ACCESS_DENIED))
        }
    }

    public func handleQueryDirectory(
        context: SMB2ServerContext,
        request: SMB2QueryDirectoryRequest,
        reply: inout SMB2QueryDirectoryReply
    ) -> SMB2ServerHandlerResult {
        lock.lock()
        guard let openFile = openFiles[request.fileId], openFile.isDirectory else {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_FILE_CLOSED))
        }

        // Check if we've already enumerated and this is a continuation
        if openFile.directoryEnumerated && (request.flags & UInt8(SMB2_RESTART_SCANS)) == 0 {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_NO_MORE_FILES))
        }

        // Mark as enumerated
        openFiles[request.fileId]?.directoryEnumerated = true
        lock.unlock()

        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(atPath: openFile.path) else {
            return .error(.init(rawValue: SMB2_STATUS_ACCESS_DENIED))
        }

        var entries: [SMB2QueryDirectoryReply.DirectoryEntry] = []

        // Add . and ..
        if let attrs = try? fileAttributes(at: openFile.path) {
            let modDate = attrs[.modificationDate] as? Date ?? Date()
            entries.append(SMB2QueryDirectoryReply.DirectoryEntry(
                name: ".",
                creationTime: modDate,
                lastAccessTime: modDate,
                lastWriteTime: modDate,
                changeTime: modDate,
                fileAttributes: UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
            ))
            entries.append(SMB2QueryDirectoryReply.DirectoryEntry(
                name: "..",
                creationTime: modDate,
                lastAccessTime: modDate,
                lastWriteTime: modDate,
                changeTime: modDate,
                fileAttributes: UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
            ))
        }

        // Add directory contents
        for name in contents {
            let fullPath = (openFile.path as NSString).appendingPathComponent(name)
            guard let attrs = try? fileAttributes(at: fullPath) else { continue }

            let fileType = attrs[.type] as? FileAttributeType
            let fileSize = attrs[.size] as? UInt64 ?? 0
            let creationDate = attrs[.creationDate] as? Date ?? Date()
            let modificationDate = attrs[.modificationDate] as? Date ?? Date()

            var fileAttrs: UInt32 = 0
            if fileType == .typeDirectory {
                fileAttrs |= UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
            } else {
                fileAttrs |= UInt32(SMB2_FILE_ATTRIBUTE_NORMAL)
            }

            entries.append(SMB2QueryDirectoryReply.DirectoryEntry(
                name: name,
                creationTime: creationDate,
                lastAccessTime: modificationDate,
                lastWriteTime: modificationDate,
                changeTime: modificationDate,
                endOfFile: fileSize,
                allocationSize: (fileSize + 4095) & ~4095,
                fileAttributes: fileAttrs
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
        guard let openFile = openFiles[request.fileId] else {
            lock.unlock()
            return .error(.init(rawValue: SMB2_STATUS_FILE_CLOSED))
        }
        lock.unlock()

        guard let attrs = try? fileAttributes(at: openFile.path) else {
            return .error(.init(rawValue: SMB2_STATUS_OBJECT_NAME_NOT_FOUND))
        }

        let fileType = attrs[.type] as? FileAttributeType
        let fileSize = attrs[.size] as? UInt64 ?? 0
        let creationDate = attrs[.creationDate] as? Date ?? Date()
        let modificationDate = attrs[.modificationDate] as? Date ?? Date()
        let isDirectory = fileType == .typeDirectory

        var fileAttrs: UInt32 = 0
        if isDirectory {
            fileAttrs |= UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
        } else {
            fileAttrs |= UInt32(SMB2_FILE_ATTRIBUTE_NORMAL)
        }

        switch request.infoType {
        case .file:
            reply.outputBuffer = buildFileInfo(
                infoClass: request.fileInfoClass,
                creationTime: creationDate,
                accessTime: modificationDate,
                writeTime: modificationDate,
                changeTime: modificationDate,
                fileSize: fileSize,
                allocationSize: (fileSize + 4095) & ~4095,
                fileAttributes: fileAttrs,
                isDirectory: isDirectory
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
        // Basic implementation - just acknowledge
        return .success
    }

    public func handleIoctl(
        context: SMB2ServerContext,
        request: SMB2IoctlRequest,
        reply: inout SMB2IoctlReply
    ) -> SMB2ServerHandlerResult {
        // Handle validate negotiate info for SMB3
        if request.ctlCode == SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO {
            return .success
        }

        return .error(.init(rawValue: SMB2_STATUS_NOT_SUPPORTED))
    }

    // MARK: - Helper Methods

    private func buildFileInfo(
        infoClass: UInt8,
        creationTime: Date,
        accessTime: Date,
        writeTime: Date,
        changeTime: Date,
        fileSize: UInt64,
        allocationSize: UInt64,
        fileAttributes: UInt32,
        isDirectory: Bool
    ) -> Data {
        var data = Data()

        switch Int32(infoClass) {
        case SMB2_FILE_BASIC_INFORMATION:
            // CreationTime, LastAccessTime, LastWriteTime, ChangeTime, FileAttributes
            appendWinTime(&data, creationTime)
            appendWinTime(&data, accessTime)
            appendWinTime(&data, writeTime)
            appendWinTime(&data, changeTime)
            appendUInt32(&data, fileAttributes)
            appendUInt32(&data, 0)  // Reserved

        case SMB2_FILE_STANDARD_INFORMATION:
            // AllocationSize, EndOfFile, NumberOfLinks, DeletePending, Directory
            appendUInt64(&data, allocationSize)
            appendUInt64(&data, fileSize)
            appendUInt32(&data, 1)  // NumberOfLinks
            data.append(0)  // DeletePending
            data.append(isDirectory ? 1 : 0)  // Directory
            appendUInt16(&data, 0)  // Reserved

        case SMB2_FILE_ALL_INFORMATION:
            // Basic info
            appendWinTime(&data, creationTime)
            appendWinTime(&data, accessTime)
            appendWinTime(&data, writeTime)
            appendWinTime(&data, changeTime)
            appendUInt32(&data, fileAttributes)
            appendUInt32(&data, 0)  // Reserved

            // Standard info
            appendUInt64(&data, allocationSize)
            appendUInt64(&data, fileSize)
            appendUInt32(&data, 1)  // NumberOfLinks
            data.append(0)  // DeletePending
            data.append(isDirectory ? 1 : 0)  // Directory
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
            // No name bytes

        case SMB2_FILE_NETWORK_OPEN_INFORMATION:
            appendWinTime(&data, creationTime)
            appendWinTime(&data, accessTime)
            appendWinTime(&data, writeTime)
            appendWinTime(&data, changeTime)
            appendUInt64(&data, allocationSize)
            appendUInt64(&data, fileSize)
            appendUInt32(&data, fileAttributes)
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
            let fsName = "AMSMB2".data(using: .utf16LittleEndian) ?? Data()
            appendUInt32(&data, UInt32(fsName.count))
            data.append(fsName)

        case SMB2_FILE_FS_VOLUME_INFORMATION:
            appendUInt64(&data, 0)  // VolumeCreationTime
            appendUInt32(&data, 0x12345678)  // VolumeSerialNumber
            let volumeLabel = "AMSMB2".data(using: .utf16LittleEndian) ?? Data()
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

    private func appendWinTime(_ data: inout Data, _ date: Date) {
        let winTime = dateToWinTime(date)
        appendUInt64(&data, winTime)
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

    private func dateToWinTime(_ date: Date) -> UInt64 {
        let windowsEpochOffset: TimeInterval = 11644473600
        let unixTime = date.timeIntervalSince1970
        let windowsTime = (unixTime + windowsEpochOffset) * 10_000_000
        return UInt64(windowsTime)
    }
}
