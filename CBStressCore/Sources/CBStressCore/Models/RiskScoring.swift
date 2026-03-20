///  RiskScoring.swift
///  CBStress
///
///  Created by Steven Petteruti on 1/24/26 exploitability ranking + public-vs-auth scoring + “compare” findings.
///  2-17-26 Make enum, struct, and let public for web app.

import Foundation

public enum RiskScoring {

    /// A result is "public" if it looks reachable without auth.
    /// (You can refine this later; this is safe and works for now.)
    public static func isPublicResult(_ result: ScanResult) -> Bool {
        // If we have explicit compare metadata, prefer it
        if result.metadata["unauthStatus"] != nil || result.metadata["authStatus"] != nil {
            // If unauth got a 2xx/3xx, treat as public
            if let unauth = result.metadata["unauthStatus"]?.intValue {
                return unauth < 400
            }
        }

        // Otherwise infer from status code (common default)
        if let code = result.statusCode {
            return code < 400
        }
        return true
    }

    /// Exploitability score: 0–100
    public static func exploitabilityScore(
        vulnerability: Vulnerability,
        isPublic: Bool,
        result: ScanResult
    ) -> Int {
        var score = 0

        // Public reachability increases exploitability
        score += isPublic ? 30 : 10

        switch vulnerability.type {
        case .exposedAPIKey:         score += 70
        case .exposedAuthToken:      score += 75
        case .authzBypass:           score += 65
        case .sensitiveData:         score += 55
        case .corsIssue:             score += 45
        case .metadataLeak:          score += 35
        case .verboseError:          score += 30
        case .missingSecurityHeader: score += 15
        case .insecureCookie:        score += 25
        case .endpointDiscovered:    score += 10
        }

        return min(100, max(0, score))
    }

    /// Risk score: 0–100
    public static func riskScore(
        vulnerability: Vulnerability,
        isPublic: Bool,
        exploitability: Int
    ) -> Int {
        var base = 0

        switch vulnerability.type {
        case .exposedAPIKey:         base = 85
        case .exposedAuthToken:      base = 90
        case .authzBypass:           base = 80
        case .sensitiveData:         base = 70
        case .insecureCookie:        base = 55
        case .corsIssue:             base = 55
        case .metadataLeak:          base = 40
        case .verboseError:          base = 35
        case .missingSecurityHeader: base = 25
        case .endpointDiscovered:    base = 15
        }

        // If not public, reduce a bit
        if !isPublic { base = Int(Double(base) * 0.85) }

        // Blend with exploitability
        let blended = Int(Double(base) * 0.65 + Double(exploitability) * 0.35)
        return min(100, max(0, blended))
    }
}
