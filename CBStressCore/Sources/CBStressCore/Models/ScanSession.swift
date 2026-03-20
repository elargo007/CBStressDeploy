///  ScanSession.swift
///  CBStress
///
///  Created by Steven Petteruti on 1/24/26 holds a run (base URL + all endpoint results + discovered graph).
///  2-17-26 Make struct public for web app

import Foundation

/// One end-to-end run: base page + discovered endpoints + scan results.
public struct ScanSession: Identifiable {
    public let id = UUID()
    public let startedAt: Date
    public let baseURL: String

    /// Results for base + discovered endpoints (order preserved as scanned).
    var results: [ScanResult]

    /// Graph edges: "from" -> "to" (usually base -> discovered endpoint).
    var edges: [(from: String, to: String)]

    /// Whether this session used auth and/or compare
    var usedAuth: Bool
    var comparedAuthVsUnauth: Bool

    public init(baseURL: String,
         results: [ScanResult],
         edges: [(String, String)],
         usedAuth: Bool,
         comparedAuthVsUnauth: Bool) {
        self.startedAt = Date()
        self.baseURL = baseURL
        self.results = results
        self.edges = edges
        self.usedAuth = usedAuth
        self.comparedAuthVsUnauth = comparedAuthVsUnauth
    }
}
