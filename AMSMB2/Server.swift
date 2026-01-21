//
//  Server.swift
//  AMSMB2
//
//  Created by Claude. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2
import SMB2.Raw

// MARK: - Server Configuration

/// Configuration for an SMB2 server instance.
public struct SMB2ServerConfiguration: Sendable {
    /// The port to listen on (default: 445)
    public var port: UInt16

    /// Maximum number of concurrent connections
    public var maxConnections: Int

    /// Server hostname
    public var hostname: String

    /// Server domain
    public var domain: String

    /// Whether message signing is enabled
    public var signingEnabled: Bool

    /// Whether anonymous access is allowed
    public var allowAnonymous: Bool

    /// Whether to act as a proxy (delegates authentication)
    public var proxyAuthentication: Bool

    /// Maximum transaction size
    public var maxTransactSize: UInt32

    /// Maximum read size
    public var maxReadSize: UInt32

    /// Maximum write size
    public var maxWriteSize: UInt32

    /// Path to Kerberos keytab file (optional)
    public var keytabPath: String?

    public init(
        port: UInt16 = 445,
        maxConnections: Int = 10,
        hostname: String = "AMSMB2Server",
        domain: String = "WORKGROUP",
        signingEnabled: Bool = true,
        allowAnonymous: Bool = false,
        proxyAuthentication: Bool = false,
        maxTransactSize: UInt32 = 1024 * 1024,
        maxReadSize: UInt32 = 1024 * 1024,
        maxWriteSize: UInt32 = 1024 * 1024,
        keytabPath: String? = nil
    ) {
        self.port = port
        self.maxConnections = maxConnections
        self.hostname = hostname
        self.domain = domain
        self.signingEnabled = signingEnabled
        self.allowAnonymous = allowAnonymous
        self.proxyAuthentication = proxyAuthentication
        self.maxTransactSize = maxTransactSize
        self.maxReadSize = maxReadSize
        self.maxWriteSize = maxWriteSize
        self.keytabPath = keytabPath
    }
}

// MARK: - Server File ID

/// Represents an SMB2 file identifier
public struct SMB2FileId: Hashable, Sendable {
    public let persistentId: UInt64
    public let volatileId: UInt64

    public init(persistentId: UInt64, volatileId: UInt64) {
        self.persistentId = persistentId
        self.volatileId = volatileId
    }

    init(_ fileId: smb2_file_id) {
        var id = fileId
        self.persistentId = withUnsafeBytes(of: &id) { buffer in
            buffer.load(fromByteOffset: 0, as: UInt64.self)
        }
        self.volatileId = withUnsafeBytes(of: &id) { buffer in
            buffer.load(fromByteOffset: 8, as: UInt64.self)
        }
    }

    func toSmb2FileId() -> smb2_file_id {
        var fileId: smb2_file_id = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        withUnsafeMutableBytes(of: &fileId) { buffer in
            buffer.storeBytes(of: persistentId.littleEndian, toByteOffset: 0, as: UInt64.self)
            buffer.storeBytes(of: volatileId.littleEndian, toByteOffset: 8, as: UInt64.self)
        }
        return fileId
    }
}

// MARK: - Server Request Types

/// Tree connect request from client
public struct SMB2TreeConnectRequest: Sendable {
    public let flags: UInt16
    public let path: String

    init(_ req: smb2_tree_connect_request) {
        self.flags = req.flags
        if let pathPtr = req.path, req.path_length > 0 {
            let utf16Ptr = UnsafeBufferPointer(start: pathPtr, count: Int(req.path_length) / 2)
            self.path = String(decoding: utf16Ptr, as: UTF16.self)
        } else {
            self.path = ""
        }
    }
}

/// Tree connect reply to client
public struct SMB2TreeConnectReply: Sendable {
    public var shareType: ShareType
    public var shareFlags: UInt32
    public var capabilities: UInt32
    public var maximalAccess: UInt32

    public enum ShareType: UInt8, Sendable {
        case disk = 0x01
        case pipe = 0x02
        case print = 0x03
    }

    public init(
        shareType: ShareType = .disk,
        shareFlags: UInt32 = 0,
        capabilities: UInt32 = 0,
        maximalAccess: UInt32 = 0x001F01FF  // Full access
    ) {
        self.shareType = shareType
        self.shareFlags = shareFlags
        self.capabilities = capabilities
        self.maximalAccess = maximalAccess
    }

    func fill(_ rep: inout smb2_tree_connect_reply) {
        rep.share_type = shareType.rawValue
        rep.share_flags = shareFlags
        rep.capabilities = capabilities
        rep.maximal_access = maximalAccess
    }
}

/// File create/open request from client
public struct SMB2CreateRequest: Sendable {
    public let securityFlags: UInt8
    public let requestedOplockLevel: UInt8
    public let impersonationLevel: UInt32
    public let desiredAccess: UInt32
    public let fileAttributes: UInt32
    public let shareAccess: UInt32
    public let createDisposition: CreateDisposition
    public let createOptions: UInt32
    public let name: String

    public enum CreateDisposition: UInt32, Sendable {
        case supersede = 0
        case open = 1
        case create = 2
        case openIf = 3
        case overwrite = 4
        case overwriteIf = 5
    }

    init(_ req: smb2_create_request) {
        self.securityFlags = req.security_flags
        self.requestedOplockLevel = req.requested_oplock_level
        self.impersonationLevel = req.impersonation_level
        self.desiredAccess = req.desired_access
        self.fileAttributes = req.file_attributes
        self.shareAccess = req.share_access
        self.createDisposition = CreateDisposition(rawValue: req.create_disposition) ?? .open
        self.createOptions = req.create_options
        self.name = req.name.map(String.init(cString:)) ?? ""
    }

    public var isDirectory: Bool {
        (createOptions & UInt32(SMB2_FILE_DIRECTORY_FILE)) != 0
    }
}

/// File create/open reply to client
public struct SMB2CreateReply: Sendable {
    public var oplockLevel: UInt8
    public var flags: UInt8
    public var createAction: CreateAction
    public var creationTime: Date
    public var lastAccessTime: Date
    public var lastWriteTime: Date
    public var changeTime: Date
    public var allocationSize: UInt64
    public var endOfFile: UInt64
    public var fileAttributes: UInt32
    public var fileId: SMB2FileId

    public enum CreateAction: UInt32, Sendable {
        case superseded = 0
        case opened = 1
        case created = 2
        case overwritten = 3
    }

    public init(
        oplockLevel: UInt8 = 0,
        flags: UInt8 = 0,
        createAction: CreateAction = .opened,
        creationTime: Date = Date(),
        lastAccessTime: Date = Date(),
        lastWriteTime: Date = Date(),
        changeTime: Date = Date(),
        allocationSize: UInt64 = 0,
        endOfFile: UInt64 = 0,
        fileAttributes: UInt32 = 0x80, // NORMAL
        fileId: SMB2FileId
    ) {
        self.oplockLevel = oplockLevel
        self.flags = flags
        self.createAction = createAction
        self.creationTime = creationTime
        self.lastAccessTime = lastAccessTime
        self.lastWriteTime = lastWriteTime
        self.changeTime = changeTime
        self.allocationSize = allocationSize
        self.endOfFile = endOfFile
        self.fileAttributes = fileAttributes
        self.fileId = fileId
    }

    func fill(_ rep: inout smb2_create_reply) {
        rep.oplock_level = oplockLevel
        rep.flags = flags
        rep.create_action = createAction.rawValue
        rep.creation_time = dateToWinTime(creationTime)
        rep.last_access_time = dateToWinTime(lastAccessTime)
        rep.last_write_time = dateToWinTime(lastWriteTime)
        rep.change_time = dateToWinTime(changeTime)
        rep.allocation_size = allocationSize
        rep.end_of_file = endOfFile
        rep.file_attributes = fileAttributes
        rep.file_id = fileId.toSmb2FileId()
    }
}

/// File close request from client
public struct SMB2CloseRequest: Sendable {
    public let flags: UInt16
    public let fileId: SMB2FileId

    init(_ req: smb2_close_request) {
        self.flags = req.flags
        self.fileId = SMB2FileId(req.file_id)
    }
}

/// File close reply to client
public struct SMB2CloseReply: Sendable {
    public var flags: UInt16
    public var creationTime: Date
    public var lastAccessTime: Date
    public var lastWriteTime: Date
    public var changeTime: Date
    public var allocationSize: UInt64
    public var endOfFile: UInt64
    public var fileAttributes: UInt32

    public init(
        flags: UInt16 = 0,
        creationTime: Date = Date(),
        lastAccessTime: Date = Date(),
        lastWriteTime: Date = Date(),
        changeTime: Date = Date(),
        allocationSize: UInt64 = 0,
        endOfFile: UInt64 = 0,
        fileAttributes: UInt32 = 0
    ) {
        self.flags = flags
        self.creationTime = creationTime
        self.lastAccessTime = lastAccessTime
        self.lastWriteTime = lastWriteTime
        self.changeTime = changeTime
        self.allocationSize = allocationSize
        self.endOfFile = endOfFile
        self.fileAttributes = fileAttributes
    }

    func fill(_ rep: inout smb2_close_reply) {
        rep.flags = flags
        rep.creation_time = dateToWinTime(creationTime)
        rep.last_access_time = dateToWinTime(lastAccessTime)
        rep.last_write_time = dateToWinTime(lastWriteTime)
        rep.change_time = dateToWinTime(changeTime)
        rep.allocation_size = allocationSize
        rep.end_of_file = endOfFile
        rep.file_attributes = fileAttributes
    }
}

/// File flush request from client
public struct SMB2FlushRequest: Sendable {
    public let fileId: SMB2FileId

    init(_ req: smb2_flush_request) {
        self.fileId = SMB2FileId(req.file_id)
    }
}

/// File read request from client
public struct SMB2ReadRequest: Sendable {
    public let flags: UInt8
    public let length: UInt32
    public let offset: UInt64
    public let fileId: SMB2FileId
    public let minimumCount: UInt32
    public let remainingBytes: UInt32

    init(_ req: smb2_read_request) {
        self.flags = req.flags
        self.length = req.length
        self.offset = req.offset
        self.fileId = SMB2FileId(req.file_id)
        self.minimumCount = req.minimum_count
        self.remainingBytes = req.remaining_bytes
    }
}

/// File read reply to client
public struct SMB2ReadReply: Sendable {
    public var dataOffset: UInt8
    public var dataRemaining: UInt32
    public var data: Data

    public init(data: Data, dataRemaining: UInt32 = 0) {
        self.dataOffset = 0x50  // Standard offset
        self.dataRemaining = dataRemaining
        self.data = data
    }

    func fill(_ rep: inout smb2_read_reply, dataBuffer: UnsafeMutablePointer<UInt8>) {
        rep.data_offset = dataOffset
        rep.data_length = UInt32(data.count)
        rep.data_remaining = dataRemaining
        data.copyBytes(to: dataBuffer, count: data.count)
        rep.data = dataBuffer
    }
}

/// File write request from client
public struct SMB2WriteRequest: Sendable {
    public let offset: UInt64
    public let fileId: SMB2FileId
    public let channel: UInt32
    public let remainingBytes: UInt32
    public let flags: UInt32
    public let data: Data

    init(_ req: smb2_write_request) {
        self.offset = req.offset
        self.fileId = SMB2FileId(req.file_id)
        self.channel = req.channel
        self.remainingBytes = req.remaining_bytes
        self.flags = req.flags
        if let buf = req.buf, req.length > 0 {
            self.data = Data(bytes: buf, count: Int(req.length))
        } else {
            self.data = Data()
        }
    }
}

/// File write reply to client
public struct SMB2WriteReply: Sendable {
    public var count: UInt32
    public var remaining: UInt32

    public init(count: UInt32, remaining: UInt32 = 0) {
        self.count = count
        self.remaining = remaining
    }

    func fill(_ rep: inout smb2_write_reply) {
        rep.count = count
        rep.remaining = remaining
    }
}

/// Query directory request from client
public struct SMB2QueryDirectoryRequest: Sendable {
    public let fileInformationClass: UInt8
    public let flags: UInt8
    public let fileIndex: UInt32
    public let fileId: SMB2FileId
    public let outputBufferLength: UInt32
    public let searchPattern: String

    init(_ req: smb2_query_directory_request) {
        self.fileInformationClass = req.file_information_class
        self.flags = req.flags
        self.fileIndex = req.file_index
        self.fileId = SMB2FileId(req.file_id)
        self.outputBufferLength = req.output_buffer_length
        self.searchPattern = req.name.map(String.init(cString:)) ?? "*"
    }
}

/// Query directory reply to client
public struct SMB2QueryDirectoryReply: Sendable {
    public var entries: [DirectoryEntry]

    public struct DirectoryEntry: Sendable {
        public var name: String
        public var fileIndex: UInt32
        public var creationTime: Date
        public var lastAccessTime: Date
        public var lastWriteTime: Date
        public var changeTime: Date
        public var endOfFile: UInt64
        public var allocationSize: UInt64
        public var fileAttributes: UInt32
        public var fileId: UInt64

        public init(
            name: String,
            fileIndex: UInt32 = 0,
            creationTime: Date = Date(),
            lastAccessTime: Date = Date(),
            lastWriteTime: Date = Date(),
            changeTime: Date = Date(),
            endOfFile: UInt64 = 0,
            allocationSize: UInt64 = 0,
            fileAttributes: UInt32 = 0x80,
            fileId: UInt64 = 0
        ) {
            self.name = name
            self.fileIndex = fileIndex
            self.creationTime = creationTime
            self.lastAccessTime = lastAccessTime
            self.lastWriteTime = lastWriteTime
            self.changeTime = changeTime
            self.endOfFile = endOfFile
            self.allocationSize = allocationSize
            self.fileAttributes = fileAttributes
            self.fileId = fileId
        }

        public var isDirectory: Bool {
            (fileAttributes & UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)) != 0
        }
    }

    public init(entries: [DirectoryEntry] = []) {
        self.entries = entries
    }
}

/// Query info request from client
public struct SMB2QueryInfoRequest: Sendable {
    public let infoType: InfoType
    public let fileInfoClass: UInt8
    public let outputBufferLength: UInt32
    public let additionalInformation: UInt32
    public let flags: UInt32
    public let fileId: SMB2FileId

    public enum InfoType: UInt8, Sendable {
        case file = 1
        case filesystem = 2
        case security = 3
        case quota = 4
    }

    init(_ req: smb2_query_info_request) {
        self.infoType = InfoType(rawValue: req.info_type) ?? .file
        self.fileInfoClass = req.file_info_class
        self.outputBufferLength = req.output_buffer_length
        self.additionalInformation = req.additional_information
        self.flags = req.flags
        self.fileId = SMB2FileId(req.file_id)
    }
}

/// Query info reply to client
public struct SMB2QueryInfoReply: Sendable {
    public var outputBuffer: Data

    public init(outputBuffer: Data = Data()) {
        self.outputBuffer = outputBuffer
    }
}

/// Set info request from client
public struct SMB2SetInfoRequest: Sendable {
    public let infoType: UInt8
    public let fileInfoClass: UInt8
    public let additionalInformation: UInt32
    public let fileId: SMB2FileId
    public let inputBuffer: Data

    init(_ req: smb2_set_info_request) {
        self.infoType = req.info_type
        self.fileInfoClass = req.file_info_class
        self.additionalInformation = req.additional_information
        self.fileId = SMB2FileId(req.file_id)
        if let data = req.input_data, req.buffer_length > 0 {
            self.inputBuffer = Data(bytes: data, count: Int(req.buffer_length))
        } else {
            self.inputBuffer = Data()
        }
    }
}

/// IOCTL request from client
public struct SMB2IoctlRequest: Sendable {
    public let ctlCode: UInt32
    public let fileId: SMB2FileId
    public let inputCount: UInt32
    public let maxInputResponse: UInt32
    public let maxOutputResponse: UInt32
    public let flags: UInt32
    public let input: Data

    init(_ req: smb2_ioctl_request) {
        self.ctlCode = req.ctl_code
        self.fileId = SMB2FileId(req.file_id)
        self.inputCount = req.input_count
        self.maxInputResponse = req.max_input_response
        self.maxOutputResponse = req.max_output_response
        self.flags = req.flags
        if let inputPtr = req.input, req.input_count > 0 {
            self.input = Data(bytes: inputPtr, count: Int(req.input_count))
        } else {
            self.input = Data()
        }
    }
}

/// IOCTL reply to client
public struct SMB2IoctlReply: Sendable {
    public var ctlCode: UInt32
    public var fileId: SMB2FileId
    public var output: Data

    public init(ctlCode: UInt32, fileId: SMB2FileId, output: Data = Data()) {
        self.ctlCode = ctlCode
        self.fileId = fileId
        self.output = output
    }
}

/// Lock request from client
public struct SMB2LockRequest: Sendable {
    public struct LockElement: Sendable {
        public let offset: UInt64
        public let length: UInt64
        public let flags: UInt32

        init(_ lock: smb2_lock_element) {
            self.offset = lock.offset
            self.length = lock.length
            self.flags = lock.flags
        }
    }

    public let fileId: SMB2FileId
    public let locks: [LockElement]

    init(_ req: smb2_lock_request) {
        self.fileId = SMB2FileId(req.file_id)
        if let locksPtr = req.locks, req.lock_count > 0 {
            var lockElements: [LockElement] = []
            for i in 0..<Int(req.lock_count) {
                lockElements.append(LockElement(locksPtr[i]))
            }
            self.locks = lockElements
        } else {
            self.locks = []
        }
    }
}

/// Change notify request from client
public struct SMB2ChangeNotifyRequest: Sendable {
    public let flags: UInt16
    public let outputBufferLength: UInt32
    public let fileId: SMB2FileId
    public let completionFilter: UInt32

    init(_ req: smb2_change_notify_request) {
        self.flags = req.flags
        self.outputBufferLength = req.output_buffer_length
        self.fileId = SMB2FileId(req.file_id)
        self.completionFilter = req.completion_filter
    }
}

/// Change notify reply to client
public struct SMB2ChangeNotifyReply: Sendable {
    public var output: Data

    public init(output: Data = Data()) {
        self.output = output
    }
}

/// Oplock break acknowledgement from client
public struct SMB2OplockBreakAcknowledgement: Sendable {
    public let oplockLevel: UInt8
    public let fileId: SMB2FileId

    init(_ req: smb2_oplock_break_acknowledgement) {
        self.oplockLevel = req.oplock_level
        self.fileId = SMB2FileId(req.file_id)
    }
}

/// Lease break acknowledgement from client
public struct SMB2LeaseBreakAcknowledgement: Sendable {
    public let flags: UInt32
    public let leaseKey: Data
    public let leaseState: UInt32
    public let leaseDuration: UInt64

    init(_ req: smb2_lease_break_acknowledgement) {
        self.flags = req.flags
        var key = req.lease_key
        self.leaseKey = withUnsafeBytes(of: &key) { Data($0) }
        self.leaseState = req.lease_state
        self.leaseDuration = req.lease_duration
    }
}

// MARK: - Handler Result

/// Result of handling a server request
public enum SMB2ServerHandlerResult: Sendable {
    /// Success - library creates reply from provided data
    case success
    /// Error - library creates error reply with given NT status
    case error(NTStatus)
    /// Handler created and queued its own reply
    case handledAsync
}

// MARK: - Server Request Handler Protocol

/// Protocol for handling SMB2 server requests
public protocol SMB2ServerRequestHandler: AnyObject, Sendable {
    /// Called when a client connection is being destroyed
    func handleDestruction(context: SMB2ServerContext) -> SMB2ServerHandlerResult

    /// Called to authorize a user
    func authorizeUser(
        context: SMB2ServerContext,
        user: String,
        domain: String,
        workstation: String
    ) -> SMB2ServerHandlerResult

    /// Called when a session is established
    func sessionEstablished(context: SMB2ServerContext) -> SMB2ServerHandlerResult

    /// Called when client logs off
    func handleLogoff(context: SMB2ServerContext) -> SMB2ServerHandlerResult

    /// Called for tree connect request
    func handleTreeConnect(
        context: SMB2ServerContext,
        request: SMB2TreeConnectRequest,
        reply: inout SMB2TreeConnectReply
    ) -> SMB2ServerHandlerResult

    /// Called for tree disconnect request
    func handleTreeDisconnect(
        context: SMB2ServerContext,
        treeId: UInt32
    ) -> SMB2ServerHandlerResult

    /// Called for file create/open request
    func handleCreate(
        context: SMB2ServerContext,
        request: SMB2CreateRequest,
        reply: inout SMB2CreateReply
    ) -> SMB2ServerHandlerResult

    /// Called for file close request
    func handleClose(
        context: SMB2ServerContext,
        request: SMB2CloseRequest,
        reply: inout SMB2CloseReply
    ) -> SMB2ServerHandlerResult

    /// Called for file flush request
    func handleFlush(
        context: SMB2ServerContext,
        request: SMB2FlushRequest
    ) -> SMB2ServerHandlerResult

    /// Called for file read request
    func handleRead(
        context: SMB2ServerContext,
        request: SMB2ReadRequest,
        reply: inout SMB2ReadReply
    ) -> SMB2ServerHandlerResult

    /// Called for file write request
    func handleWrite(
        context: SMB2ServerContext,
        request: SMB2WriteRequest,
        reply: inout SMB2WriteReply
    ) -> SMB2ServerHandlerResult

    /// Called for directory query request
    func handleQueryDirectory(
        context: SMB2ServerContext,
        request: SMB2QueryDirectoryRequest,
        reply: inout SMB2QueryDirectoryReply
    ) -> SMB2ServerHandlerResult

    /// Called for query info request
    func handleQueryInfo(
        context: SMB2ServerContext,
        request: SMB2QueryInfoRequest,
        reply: inout SMB2QueryInfoReply
    ) -> SMB2ServerHandlerResult

    /// Called for set info request
    func handleSetInfo(
        context: SMB2ServerContext,
        request: SMB2SetInfoRequest
    ) -> SMB2ServerHandlerResult

    /// Called for IOCTL request
    func handleIoctl(
        context: SMB2ServerContext,
        request: SMB2IoctlRequest,
        reply: inout SMB2IoctlReply
    ) -> SMB2ServerHandlerResult

    /// Called for lock request
    func handleLock(
        context: SMB2ServerContext,
        request: SMB2LockRequest
    ) -> SMB2ServerHandlerResult

    /// Called for cancel request
    func handleCancel(context: SMB2ServerContext) -> SMB2ServerHandlerResult

    /// Called for echo request
    func handleEcho(context: SMB2ServerContext) -> SMB2ServerHandlerResult

    /// Called for change notify request
    func handleChangeNotify(
        context: SMB2ServerContext,
        request: SMB2ChangeNotifyRequest,
        reply: inout SMB2ChangeNotifyReply
    ) -> SMB2ServerHandlerResult

    /// Called for oplock break acknowledgement
    func handleOplockBreak(
        context: SMB2ServerContext,
        request: SMB2OplockBreakAcknowledgement
    ) -> SMB2ServerHandlerResult

    /// Called for lease break acknowledgement
    func handleLeaseBreak(
        context: SMB2ServerContext,
        request: SMB2LeaseBreakAcknowledgement
    ) -> SMB2ServerHandlerResult
}

// MARK: - Default Handler Implementations

public extension SMB2ServerRequestHandler {
    func handleDestruction(context: SMB2ServerContext) -> SMB2ServerHandlerResult {
        .success
    }

    func sessionEstablished(context: SMB2ServerContext) -> SMB2ServerHandlerResult {
        .success
    }

    func handleLogoff(context: SMB2ServerContext) -> SMB2ServerHandlerResult {
        .success
    }

    func handleFlush(context: SMB2ServerContext, request: SMB2FlushRequest) -> SMB2ServerHandlerResult {
        .success
    }

    func handleLock(context: SMB2ServerContext, request: SMB2LockRequest) -> SMB2ServerHandlerResult {
        .success
    }

    func handleCancel(context: SMB2ServerContext) -> SMB2ServerHandlerResult {
        .success
    }

    func handleEcho(context: SMB2ServerContext) -> SMB2ServerHandlerResult {
        .success
    }

    func handleChangeNotify(
        context: SMB2ServerContext,
        request: SMB2ChangeNotifyRequest,
        reply: inout SMB2ChangeNotifyReply
    ) -> SMB2ServerHandlerResult {
        .error(.init(rawValue: SMB2_STATUS_NOT_SUPPORTED))
    }

    func handleOplockBreak(
        context: SMB2ServerContext,
        request: SMB2OplockBreakAcknowledgement
    ) -> SMB2ServerHandlerResult {
        .success
    }

    func handleLeaseBreak(
        context: SMB2ServerContext,
        request: SMB2LeaseBreakAcknowledgement
    ) -> SMB2ServerHandlerResult {
        .success
    }
}

// MARK: - Server Context

/// Represents a client connection context
public final class SMB2ServerContext: @unchecked Sendable {
    internal let smb2: UnsafeMutablePointer<smb2_context>
    internal weak var server: SMB2Server?

    /// User data associated with this context
    public var userData: (any Sendable)?

    init(smb2: UnsafeMutablePointer<smb2_context>, server: SMB2Server) {
        self.smb2 = smb2
        self.server = server
    }

    /// The user associated with this connection
    public var user: String? {
        smb2.pointee.user.map(String.init(cString:))
    }

    /// The domain associated with this connection
    public var domain: String? {
        smb2.pointee.domain.map(String.init(cString:))
    }

    /// The workstation associated with this connection
    public var workstation: String? {
        smb2.pointee.workstation.map(String.init(cString:))
    }

    /// The current tree ID
    public var treeId: UInt32 {
        let cur = smb2.pointee.tree_id_cur
        guard cur >= 0 else { return 0 }
        return withUnsafeBytes(of: smb2.pointee.tree_id) { buffer in
            buffer.load(fromByteOffset: Int(cur) * MemoryLayout<UInt32>.size, as: UInt32.self)
        }
    }

    /// The session ID
    public var sessionId: UInt64 {
        smb2.pointee.session_id
    }

    /// Set the password for NTLM authentication
    public func setPassword(_ password: String) {
        smb2_set_password(smb2, password)
    }

    /// Set password from NTLM_USER_FILE
    public func setPasswordFromFile() {
        smb2_set_password_from_file(smb2)
    }
}

// MARK: - SMB2 Server

/// SMB2 Server implementation
public final class SMB2Server: @unchecked Sendable {
    private var server: smb2_server
    private var handlers: smb2_server_request_handlers
    private let handler: any SMB2ServerRequestHandler
    private var contexts: [UnsafeMutablePointer<smb2_context>: SMB2ServerContext] = [:]
    private let lock = NSLock()
    private var isRunning = false
    private var serverQueue: DispatchQueue

    /// The configuration for this server
    public let configuration: SMB2ServerConfiguration

    /// Create a new SMB2 server
    public init(configuration: SMB2ServerConfiguration, handler: any SMB2ServerRequestHandler) {
        self.configuration = configuration
        self.handler = handler
        self.serverQueue = DispatchQueue(label: "com.amsmb2.server", qos: .userInitiated)

        // Initialize server structure
        self.server = smb2_server()
        self.handlers = smb2_server_request_handlers()

        // Configure server
        configuration.hostname.withCString { hostname in
            _ = withUnsafeMutableBytes(of: &server.hostname) { buffer in
                strncpy(buffer.baseAddress!.assumingMemoryBound(to: CChar.self), hostname, 127)
            }
        }

        configuration.domain.withCString { domain in
            _ = withUnsafeMutableBytes(of: &server.domain) { buffer in
                strncpy(buffer.baseAddress!.assumingMemoryBound(to: CChar.self), domain, 127)
            }
        }

        if let keytabPath = configuration.keytabPath {
            keytabPath.withCString { keytab in
                _ = withUnsafeMutableBytes(of: &server.keytab_path) { buffer in
                    strncpy(buffer.baseAddress!.assumingMemoryBound(to: CChar.self), keytab, 255)
                }
            }
        }

        // Generate server GUID
        let uuid = UUID()
        withUnsafeMutableBytes(of: &server.guid) { buffer in
            withUnsafeBytes(of: uuid.uuid) { uuidBytes in
                buffer.copyMemory(from: uuidBytes)
            }
        }

        server.port = configuration.port
        server.max_transact_size = configuration.maxTransactSize
        server.max_read_size = configuration.maxReadSize
        server.max_write_size = configuration.maxWriteSize
        server.signing_enabled = configuration.signingEnabled ? 1 : 0
        server.allow_anonymous = configuration.allowAnonymous ? 1 : 0
        server.proxy_authentication = configuration.proxyAuthentication ? 1 : 0

        // Set up handlers - this must be done before start() is called
        // The handlers are set in start() since we need a stable pointer
        setupHandlerCallbacks()
    }

    deinit {
        stop()
    }

    private func setupHandlerCallbacks() {
        handlers.destruction_event = { srvr, smb2 in
            guard let smb2 = smb2, let srvr = srvr else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                server.handler.handleDestruction(context: context).toInt32()
            }
        }

        handlers.authorize_user = { srvr, smb2, user, domain, workstation in
            guard let smb2 = smb2, let srvr = srvr else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let userStr = user.map(String.init(cString:)) ?? ""
                let domainStr = domain.map(String.init(cString:)) ?? ""
                let workstationStr = workstation.map(String.init(cString:)) ?? ""
                return server.handler.authorizeUser(
                    context: context,
                    user: userStr,
                    domain: domainStr,
                    workstation: workstationStr
                ).toInt32()
            }
        }

        handlers.session_established = { srvr, smb2 in
            guard let smb2 = smb2, let srvr = srvr else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                server.handler.sessionEstablished(context: context).toInt32()
            }
        }

        handlers.logoff_cmd = { srvr, smb2 in
            guard let smb2 = smb2, let srvr = srvr else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                server.handler.handleLogoff(context: context).toInt32()
            }
        }

        handlers.tree_connect_cmd = { srvr, smb2, req, rep in
            guard let smb2 = smb2, let srvr = srvr, let req = req, let rep = rep else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2TreeConnectRequest(req.pointee)
                var reply = SMB2TreeConnectReply()
                let result = server.handler.handleTreeConnect(
                    context: context,
                    request: request,
                    reply: &reply
                )
                reply.fill(&rep.pointee)
                return result.toInt32()
            }
        }

        handlers.tree_disconnect_cmd = { srvr, smb2, treeId in
            guard let smb2 = smb2, let srvr = srvr else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                server.handler.handleTreeDisconnect(context: context, treeId: treeId).toInt32()
            }
        }

        handlers.create_cmd = { srvr, smb2, req, rep in
            guard let smb2 = smb2, let srvr = srvr, let req = req, let rep = rep else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2CreateRequest(req.pointee)
                var reply = SMB2CreateReply(fileId: SMB2FileId(persistentId: 0, volatileId: 0))
                let result = server.handler.handleCreate(
                    context: context,
                    request: request,
                    reply: &reply
                )
                reply.fill(&rep.pointee)
                return result.toInt32()
            }
        }

        handlers.close_cmd = { srvr, smb2, req, rep in
            guard let smb2 = smb2, let srvr = srvr, let req = req, let rep = rep else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2CloseRequest(req.pointee)
                var reply = SMB2CloseReply()
                let result = server.handler.handleClose(
                    context: context,
                    request: request,
                    reply: &reply
                )
                reply.fill(&rep.pointee)
                return result.toInt32()
            }
        }

        handlers.flush_cmd = { srvr, smb2, req in
            guard let smb2 = smb2, let srvr = srvr, let req = req else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2FlushRequest(req.pointee)
                return server.handler.handleFlush(context: context, request: request).toInt32()
            }
        }

        handlers.read_cmd = { srvr, smb2, req, rep in
            guard let smb2 = smb2, let srvr = srvr, let req = req, let rep = rep else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2ReadRequest(req.pointee)
                var reply = SMB2ReadReply(data: Data())
                let result = server.handler.handleRead(
                    context: context,
                    request: request,
                    reply: &reply
                )
                if case .success = result, !reply.data.isEmpty {
                    let dataBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: reply.data.count)
                    reply.fill(&rep.pointee, dataBuffer: dataBuffer)
                }
                return result.toInt32()
            }
        }

        handlers.write_cmd = { srvr, smb2, req, rep in
            guard let smb2 = smb2, let srvr = srvr, let req = req, let rep = rep else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2WriteRequest(req.pointee)
                var reply = SMB2WriteReply(count: 0)
                let result = server.handler.handleWrite(
                    context: context,
                    request: request,
                    reply: &reply
                )
                reply.fill(&rep.pointee)
                return result.toInt32()
            }
        }

        handlers.query_directory_cmd = { srvr, smb2, req, rep in
            guard let smb2 = smb2, let srvr = srvr, let req = req, let rep = rep else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2QueryDirectoryRequest(req.pointee)
                var reply = SMB2QueryDirectoryReply()
                let result = server.handler.handleQueryDirectory(
                    context: context,
                    request: request,
                    reply: &reply
                )

                if case .success = result, !reply.entries.isEmpty {
                    // Encode directory entries into SMB2 format
                    let (buffer, length) = encodeDirectoryEntries(smb2, reply.entries)
                    rep.pointee.output_buffer = buffer?.assumingMemoryBound(to: UInt8.self)
                    rep.pointee.output_buffer_length = length
                } else if case .success = result {
                    // Empty directory or no more entries
                    rep.pointee.output_buffer = nil
                    rep.pointee.output_buffer_length = 0
                }

                return result.toInt32()
            }
        }

        handlers.query_info_cmd = { srvr, smb2, req, rep in
            guard let smb2 = smb2, let srvr = srvr, let req = req, let rep = rep else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2QueryInfoRequest(req.pointee)
                var reply = SMB2QueryInfoReply()
                let result = server.handler.handleQueryInfo(
                    context: context,
                    request: request,
                    reply: &reply
                )
                if case .success = result, !reply.outputBuffer.isEmpty {
                    // Allocate buffer and copy data
                    let buffer = UnsafeMutableRawPointer.allocate(
                        byteCount: reply.outputBuffer.count,
                        alignment: 8
                    )
                    reply.outputBuffer.copyBytes(
                        to: buffer.assumingMemoryBound(to: UInt8.self),
                        count: reply.outputBuffer.count
                    )
                    rep.pointee.output_buffer = buffer
                    rep.pointee.output_buffer_length = UInt32(reply.outputBuffer.count)
                }
                return result.toInt32()
            }
        }

        handlers.set_info_cmd = { srvr, smb2, req in
            guard let smb2 = smb2, let srvr = srvr, let req = req else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2SetInfoRequest(req.pointee)
                return server.handler.handleSetInfo(context: context, request: request).toInt32()
            }
        }

        handlers.ioctl_cmd = { srvr, smb2, req, rep in
            guard let smb2 = smb2, let srvr = srvr, let req = req, let rep = rep else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2IoctlRequest(req.pointee)
                var reply = SMB2IoctlReply(ctlCode: request.ctlCode, fileId: request.fileId)
                let result = server.handler.handleIoctl(
                    context: context,
                    request: request,
                    reply: &reply
                )
                rep.pointee.ctl_code = reply.ctlCode
                rep.pointee.file_id = reply.fileId.toSmb2FileId()
                return result.toInt32()
            }
        }

        handlers.lock_cmd = { srvr, smb2, req in
            guard let smb2 = smb2, let srvr = srvr, let req = req else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2LockRequest(req.pointee)
                return server.handler.handleLock(context: context, request: request).toInt32()
            }
        }

        handlers.cancel_cmd = { srvr, smb2 in
            guard let smb2 = smb2, let srvr = srvr else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                server.handler.handleCancel(context: context).toInt32()
            }
        }

        handlers.echo_cmd = { srvr, smb2 in
            guard let smb2 = smb2, let srvr = srvr else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                server.handler.handleEcho(context: context).toInt32()
            }
        }

        handlers.change_notify_cmd = { srvr, smb2, req, rep in
            guard let smb2 = smb2, let srvr = srvr, let req = req, let rep = rep else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2ChangeNotifyRequest(req.pointee)
                var reply = SMB2ChangeNotifyReply()
                let result = server.handler.handleChangeNotify(
                    context: context,
                    request: request,
                    reply: &reply
                )
                return result.toInt32()
            }
        }

        handlers.oplock_break_cmd = { srvr, smb2, req in
            guard let smb2 = smb2, let srvr = srvr, let req = req else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2OplockBreakAcknowledgement(req.pointee)
                return server.handler.handleOplockBreak(context: context, request: request).toInt32()
            }
        }

        handlers.lease_break_cmd = { srvr, smb2, req in
            guard let smb2 = smb2, let srvr = srvr, let req = req else { return -1 }
            return SMB2Server.handleRequest(srvr: srvr, smb2: smb2) { server, context in
                let request = SMB2LeaseBreakAcknowledgement(req.pointee)
                return server.handler.handleLeaseBreak(context: context, request: request).toInt32()
            }
        }

        server.handlers = withUnsafeMutablePointer(to: &handlers) { $0 }
    }

    private static func handleRequest(
        srvr: UnsafeMutablePointer<smb2_server>,
        smb2: UnsafeMutablePointer<smb2_context>,
        handler: (SMB2Server, SMB2ServerContext) -> Int32
    ) -> Int32 {
        // Retrieve the server instance from the server pointer
        guard let serverPtr = srvr.pointee.auth_data else { return -1 }
        let server = Unmanaged<SMB2Server>.fromOpaque(serverPtr).takeUnretainedValue()

        server.lock.lock()
        defer { server.lock.unlock() }

        let context: SMB2ServerContext
        if let existingContext = server.contexts[smb2] {
            context = existingContext
        } else {
            context = SMB2ServerContext(smb2: smb2, server: server)
            server.contexts[smb2] = context
        }

        return handler(server, context)
    }

    /// Start the server and begin listening for connections
    /// This method blocks until the server is stopped.
    public func start() throws {
        guard !isRunning else { return }

        isRunning = true

        // Store self reference for callbacks
        let selfPtr = Unmanaged.passRetained(self).toOpaque()
        server.auth_data = selfPtr

        // Set the handlers pointer - we use withUnsafeMutablePointer to get a stable pointer
        // The handlers struct is stored in self, so it will live as long as the server
        let result: Int32 = withUnsafeMutablePointer(to: &handlers) { handlersPtr in
            server.handlers = handlersPtr

            let clientConnectionCallback: smb2_client_connection = { smb2, cbData in
                guard let smb2 = smb2, let cbData = cbData else { return }
                let server = Unmanaged<SMB2Server>.fromOpaque(cbData).takeUnretainedValue()

                server.lock.lock()
                let context = SMB2ServerContext(smb2: smb2, server: server)
                server.contexts[smb2] = context
                server.lock.unlock()
            }

            // smb2_serve_port is blocking - it handles bind, listen, and the event loop
            return smb2_serve_port(&server, Int32(configuration.maxConnections), clientConnectionCallback, selfPtr)
        }

        isRunning = false

        // Release self reference
        Unmanaged<SMB2Server>.fromOpaque(selfPtr).release()
        server.auth_data = nil

        if result != 0 {
            throw POSIXError(.init(-result), description: "Server error")
        }
    }

    /// Start the server asynchronously in a background queue
    public func startAsync() {
        serverQueue.async { [weak self] in
            try? self?.start()
        }
    }

    /// Stop the server
    public func stop() {
        guard isRunning else { return }
        isRunning = false

        if server.fd >= 0 {
            close(server.fd)
            server.fd = -1
        }

        // Clean up contexts
        lock.lock()
        contexts.removeAll()
        lock.unlock()
    }

    /// Check if the server is currently running
    public var running: Bool {
        isRunning
    }
}

// MARK: - Helper Functions

private extension SMB2ServerHandlerResult {
    func toInt32() -> Int32 {
        switch self {
        case .success:
            return 0
        case .error(let status):
            return Int32(bitPattern: status.rawValue)
        case .handledAsync:
            return 1
        }
    }
}

/// Convert a Date to Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
private func dateToWinTime(_ date: Date) -> UInt64 {
    // Windows epoch is Jan 1, 1601; Unix epoch is Jan 1, 1970
    // Difference is 11644473600 seconds
    let windowsEpochOffset: TimeInterval = 11644473600
    let unixTime = date.timeIntervalSince1970
    let windowsTime = (unixTime + windowsEpochOffset) * 10_000_000
    return UInt64(windowsTime)
}

/// Convert Windows FILETIME to Date
func winTimeToDate(_ winTime: UInt64) -> Date {
    let windowsEpochOffset: TimeInterval = 11644473600
    let unixTime = TimeInterval(winTime) / 10_000_000 - windowsEpochOffset
    return Date(timeIntervalSince1970: unixTime)
}

/// Encode directory entries into SMB2 FileIdBothDirectoryInformation format
/// Returns allocated buffer that must be freed by caller
/// Note: The buffer contains smb2_fileidbothdirectoryinformation structures with name pointers
func encodeDirectoryEntries(
    _ smb2: UnsafeMutablePointer<smb2_context>,
    _ entries: [SMB2QueryDirectoryReply.DirectoryEntry]
) -> (buffer: UnsafeMutableRawPointer?, length: UInt32) {
    guard !entries.isEmpty else { return (nil, 0) }

    // The libsmb2 library expects smb2_fileidbothdirectoryinformation structures
    // with 'name' field as a pointer to UTF-8 string. The library then converts to UTF-16.
    // Structure size is aligned to 64-bit boundary

    let structSize = MemoryLayout<smb2_fileidbothdirectoryinformation>.stride
    let paddedStructSize = (structSize + 7) & ~7
    let totalSize = paddedStructSize * entries.count

    // Allocate buffer for structures
    let buffer = UnsafeMutableRawPointer.allocate(byteCount: totalSize, alignment: 8)
    buffer.initializeMemory(as: UInt8.self, repeating: 0, count: totalSize)

    for (index, entry) in entries.enumerated() {
        let isLast = index == entries.count - 1
        let ptr = buffer.advanced(by: index * paddedStructSize)
            .assumingMemoryBound(to: smb2_fileidbothdirectoryinformation.self)

        // Allocate and copy the name as a C string
        let nameCString = strdup(entry.name)

        var info = smb2_fileidbothdirectoryinformation()
        info.next_entry_offset = isLast ? 0 : UInt32(paddedStructSize)
        info.file_index = entry.fileIndex

        // Convert dates to smb2_timeval
        info.creation_time = smb2_timeval(
            tv_sec: Int(entry.creationTime.timeIntervalSince1970),
            tv_usec: 0
        )
        info.last_access_time = smb2_timeval(
            tv_sec: Int(entry.lastAccessTime.timeIntervalSince1970),
            tv_usec: 0
        )
        info.last_write_time = smb2_timeval(
            tv_sec: Int(entry.lastWriteTime.timeIntervalSince1970),
            tv_usec: 0
        )
        info.change_time = smb2_timeval(
            tv_sec: Int(entry.changeTime.timeIntervalSince1970),
            tv_usec: 0
        )

        info.end_of_file = entry.endOfFile
        info.allocation_size = entry.allocationSize
        info.file_attributes = entry.fileAttributes
        info.file_name_length = UInt32(entry.name.utf16.count * 2)
        info.ea_size = 0
        info.short_name_length = 0  // No 8.3 short name provided
        info.file_id = entry.fileId
        info.name = UnsafePointer(nameCString)

        ptr.pointee = info
    }

    return (buffer, UInt32(totalSize))
}
