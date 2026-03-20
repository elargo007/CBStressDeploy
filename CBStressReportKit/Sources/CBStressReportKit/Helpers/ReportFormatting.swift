//
//  ReportFormatting.swift
//  CBStressReportKit
//
//  Created by Steven Petteruti on 3/14/26.
//

import Foundation
import CBStressCore

public enum ReportFormatting {
    public static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .medium
        return f
    }()

    public static func timestamp(_ date: Date) -> String {
        dateFormatter.string(from: date)
    }

    public static func responseTimeString(_ seconds: Double?) -> String {
        guard let seconds else { return "—" }
        return String(format: "%.3f sec", seconds)
    }

    public static func statusString(_ code: Int?) -> String {
        guard let code else { return "—" }
        return "\(code)"
    }

    public static func headerCount(_ result: ScanResult) -> String {
        "\(result.responseHeaders.count)"
    }

    public static func findingsCount(_ result: ScanResult) -> String {
        "\(result.vulnerabilities.count)"
    }
}

public extension Vulnerability {
    var reportCategoryLabel: String {
        switch type {
        case .missingSecurityHeader:
            return "HEADER"
        case .verboseError:
            return "ERROR"
        case .exposedAPIKey:
            return "API KEY"
        case .exposedAuthToken:
            return "TOKEN"
        case .sensitiveData:
            return "DATA"
        case .insecureCookie:
            return "COOKIE"
        default:
            return "GENERAL"
        }
    }

    var reportRiskScore: Int {
        switch type {
        case .missingSecurityHeader: return 41
        case .verboseError: return 60
        case .insecureCookie: return 55
        case .exposedAuthToken: return 88
        case .exposedAPIKey: return 92
        case .sensitiveData: return 85
        default: return 35
        }
    }

    var reportExploitabilityScore: Int {
        switch type {
        case .missingSecurityHeader: return 34
        case .verboseError: return 48
        case .insecureCookie: return 52
        case .exposedAuthToken: return 84
        case .exposedAPIKey: return 90
        case .sensitiveData: return 74
        default: return 30
        }
    }
}
