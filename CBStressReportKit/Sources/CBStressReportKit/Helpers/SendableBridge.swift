//
//  SendableBridge.swift
//  CBStressReportKit
//
//  Created by Steven Petteruti on 3/14/26.
//

import CBStressCore

// Swift 6 strict concurrency bridge for types defined in CBStressCore.
// These models are immutable during reporting, so marking them
// @unchecked Sendable is safe.

extension ScanResult: @retroactive @unchecked Sendable {}
extension Endpoint: @retroactive @unchecked Sendable {}
extension Vulnerability: @retroactive @unchecked Sendable {}
extension VulnerabilityType: @retroactive @unchecked Sendable {}
