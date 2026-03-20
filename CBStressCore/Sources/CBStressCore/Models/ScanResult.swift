///  ScanResult.swift
///  CBStress
///
///  Created by Steven Petteruti on 1/16/26.
///  1-24-26 Define Scan Result
///  2-17-26 Make struct public for web app

import Foundation

public struct ScanResult: Identifiable, Codable, Hashable {

    public var id: UUID
    public var endpoint: Endpoint

    // These are exactly the properties your UI and scanner are trying to read/write
    public var statusCode: Int?
    public var responseTime: TimeInterval?
    public var responseHeaders: [String: String]
    public var vulnerabilities: [Vulnerability]

    // Keeps your existing “metadata” usage in NetworkScanner (bodyString, unauthStatus, etc.)
    // Requires AnyCodable to be public.
    public var metadata: [String: AnyCodable]

    public init(
        id: UUID = UUID(),
        endpoint: Endpoint,
        statusCode: Int? = nil,
        responseTime: TimeInterval? = nil,
        responseHeaders: [String: String] = [:],
        vulnerabilities: [Vulnerability] = [],
        metadata: [String: AnyCodable] = [:]
    ) {
        self.id = id
        self.endpoint = endpoint
        self.statusCode = statusCode
        self.responseTime = responseTime
        self.responseHeaders = responseHeaders
        self.vulnerabilities = vulnerabilities
        self.metadata = metadata
    }
}
