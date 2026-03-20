//
//  ScanReport.swift
//  CBStressReportKit
//
//  Created by Steven Petteruti on 3/14/26.
//

import Foundation
import CBStressCore

public struct ScanReport: Codable, Sendable {
    public let title: String
    public let generatedAt: Date
    public let result: ScanResult

    public init(
        title: String = "CBStress Results",
        generatedAt: Date = Date(),
        result: ScanResult
    ) {
        self.title = title
        self.generatedAt = generatedAt
        self.result = result
    }
}
