///  APIKeyDetector.swift
///  CBStress
///
///  Created by Steven Petteruti on 1/16/26.
///  1-24-26 Define APIKeyDetector.detect(in: String) -> [Vulnerability]
///  1-28-26 Add Airwallex, Phoenix, Braintree, Shopify, Authorize.net, NMI api key detection.
///  2-17-26 Make enum public for web app


import Foundation

/// Detects exposed API keys, auth tokens, and session artifacts in response bodies.
/// NOTE: Uses the project’s top-level VulnerabilityType + Vulnerability(type, description, evidence).
public enum APIKeyDetector {

    /// Scans raw text and returns Vulnerability objects for any detected secrets.
    static func detect(in text: String) -> [Vulnerability] {
        var vulns: [Vulnerability] = []
        var seen = Set<String>() // de-dupe by (type + value)

        // (regex pattern, vulnerability type, human-readable label)
        let patterns: [(String, VulnerabilityType, String)] = [
            // Common cloud / dev tokens
            (#"AKIA[0-9A-Z]{16}"#, .exposedAPIKey, "AWS Access Key"),
            (#"AIza[0-9A-Za-z\-_]{35}"#, .exposedAPIKey, "Google API Key"),
            (#"sk_live_[0-9a-zA-Z]{24,}"#, .exposedAPIKey, "Stripe Live Key"),
            (#"sk-[A-Za-z0-9]{48}"#, .exposedAPIKey, "OpenAI API Key"),
            (#"ghp_[0-9A-Za-z]{36}"#, .exposedAPIKey, "GitHub Personal Access Token"),
            (#"xox[baprs]-[0-9A-Za-z\-]{10,}"#, .exposedAPIKey, "Slack Token"),
            (#"ya29\.[0-9A-Za-z\-_]+"#, .exposedAuthToken, "Google OAuth Token"),

            // --- Payments / commerce platforms (added) ---

            // Braintree (access token + public key)
            (#"access_token\$(?:production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32}"#, .exposedAPIKey, "Braintree Access Token"),
            (#"(?i)\bbraintree_(?:production|sandbox)_[0-9a-z]{16}\b"#, .exposedAPIKey, "Braintree Token (heuristic)"),
            (#"(?i)\b(?:sandbox|production)_[0-9a-z]{6,16}_[0-9a-z]{32}\b"#, .exposedAPIKey, "Braintree Public Key (heuristic)"),

            // Shopify (Admin / Storefront / access tokens are often shown in headers,
            // but occasionally leak in bodies/logs)
            (#"shpat_[0-9a-fA-F]{32}"#, .exposedAPIKey, "Shopify Admin Access Token"),
            (#"shpua_[0-9a-fA-F]{32}"#, .exposedAPIKey, "Shopify User Access Token"),
            (#"shpss_[0-9a-fA-F]{32}"#, .exposedAPIKey, "Shopify Shared Secret"),
            (#"shpca_[0-9a-fA-F]{32}"#, .exposedAPIKey, "Shopify Custom App Token"),

            // Authorize.Net (transaction key is historically 16 chars, but can vary; detect typical hex-ish keys)
            // Also catch common variable names where keys leak into JS/JSON.
            (#"(?i)\b(?:authorize\.net|authorizenet)\b.*?\btransaction[_-]?key\b\s*[:=]\s*['\"][A-Za-z0-9]{12,40}['\"]"#,
             .exposedAPIKey, "Authorize.Net Transaction Key (heuristic)"),
            (#"(?i)\btransaction[_-]?key\b\s*[:=]\s*['\"][A-Za-z0-9]{12,40}['\"]"#,
             .exposedAPIKey, "Authorize.Net Transaction Key (heuristic)"),

            // NMI (Network Merchants) – API keys vary; detect common key variable patterns and long token-like values
            (#"(?i)\b(?:nmi|networkmerchants)\b.*?\b(?:api[_-]?key|security[_-]?key|private[_-]?key)\b\s*[:=]\s*['\"][A-Za-z0-9]{16,64}['\"]"#,
             .exposedAPIKey, "NMI API Key (heuristic)"),
            (#"(?i)\b(?:api[_-]?key|security[_-]?key|private[_-]?key)\b\s*[:=]\s*['\"][A-Za-z0-9]{16,64}['\"]"#,
             .exposedAPIKey, "NMI API Key (heuristic)"),

            // Airwallex – keys commonly appear as "client_id"/"api_key"/"apiKey" in configs; format can vary
            (#"(?i)\b(?:airwallex)\b.*?\b(?:api[_-]?key|client[_-]?id|client[_-]?secret|apiKey)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,80}['\"]"#,
             .exposedAPIKey, "Airwallex Credential (heuristic)"),
            (#"(?i)\b(?:api[_-]?key|client[_-]?id|client[_-]?secret|apiKey)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,80}['\"]"#,
             .exposedAPIKey, "Airwallex Credential (heuristic)"),

            // Phoenix (provider name is ambiguous across ecosystems; treat as generic “Phoenix API key” heuristics)
            (#"(?i)\bphoenix\b.*?\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,80}['\"]"#,
             .exposedAPIKey, "Phoenix API Key/Token (heuristic)"),
            (#"(?i)\b(?:phoenixApiKey|phoenix_api_key|phoenixToken|phoenix_token)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,80}['\"]"#,
             .exposedAPIKey, "Phoenix API Key/Token (heuristic)"),

            // JWT-like tokens (3 dot-separated base64url-ish segments)
            (#"[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"#, .exposedAuthToken, "JWT / Bearer Token")
        ]

        for (pattern, type, label) in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { continue }

            let range = NSRange(text.startIndex..., in: text)
            for match in regex.matches(in: text, range: range) {
                guard let r = Range(match.range, in: text) else { continue }
                let found = String(text[r])

                // Reduce JWT false positives: require 3 parts and each part reasonably long
                if type == .exposedAuthToken, label.contains("JWT") {
                    let parts = found.split(separator: ".")
                    if parts.count != 3 || parts.contains(where: { $0.count < 12 }) { continue }
                }

                // For heuristic “key: 'value'” patterns, mask the value segment if possible
                let evidenceValue = extractQuotedSecret(from: found) ?? found

                let key = "\(type.rawValue)|\(evidenceValue)"
                guard !seen.contains(key) else { continue }
                seen.insert(key)

                vulns.append(
                    Vulnerability(
                        type: type,
                        description: "Exposed \(label) in response body",
                        evidence: mask(evidenceValue)
                    )
                )
            }
        }

        // Cookie / session heuristics (best-effort; only works if cookie-like strings are present in body text)
        vulns.append(contentsOf: detectCookieIssues(in: text))

        return vulns
    }

    // MARK: - Cookie heuristics (body-text only)

    private static func detectCookieIssues(in text: String) -> [Vulnerability] {
        var out: [Vulnerability] = []
        let lower = text.lowercased()

        // Body rarely contains Set-Cookie, but sometimes HTML pages echo it (or debugging output exists).
        guard lower.contains("set-cookie") else { return out }

        if !lower.contains("httponly") {
            out.append(
                Vulnerability(
                    type: .insecureCookie,
                    description: "Session cookie appears to be missing HttpOnly flag (heuristic)",
                    evidence: "Found 'Set-Cookie' but not 'HttpOnly' in body text"
                )
            )
        }

        if !lower.contains("secure") {
            out.append(
                Vulnerability(
                    type: .insecureCookie,
                    description: "Session cookie appears to be missing Secure flag (heuristic)",
                    evidence: "Found 'Set-Cookie' but not 'Secure' in body text"
                )
            )
        }

        if !lower.contains("samesite") {
            out.append(
                Vulnerability(
                    type: .insecureCookie,
                    description: "Session cookie appears to be missing SameSite attribute (heuristic)",
                    evidence: "Found 'Set-Cookie' but not 'SameSite' in body text"
                )
            )
        }

        return out
    }

    // MARK: - Helpers

    /// Attempts to extract the secret inside quotes for patterns that include `key: "value"`.
    private static func extractQuotedSecret(from snippet: String) -> String? {
        // Find first quoted region: "..." or '...'
        // Keep it simple + safe; if it fails, we just use the whole snippet.
        let patterns = [
            #"'([^'\n\r]{6,200})'"#,
            #""([^"\n\r]{6,200})""#
        ]
        for p in patterns {
            if let re = try? NSRegularExpression(pattern: p) {
                let ns = snippet as NSString
                let range = NSRange(location: 0, length: ns.length)
                if let m = re.firstMatch(in: snippet, range: range),
                   m.numberOfRanges >= 2 {
                    let val = ns.substring(with: m.range(at: 1))
                    return val
                }
            }
        }
        return nil
    }

    // MARK: - Masking

    /// Avoid logging full secrets into UI/PDF; keep enough to correlate.
    private static func mask(_ value: String) -> String {
        let t = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.count > 14 else { return "••••" }
        return "\(t.prefix(6))••••\(t.suffix(6))"
    }
}
