///  AuthTokenHeuristics.swift
///  CBStress
///
///  Created by Steven Petteruti on 1/24/26 for JWT + bearer + cookie checks.
///  2-17-26 Make enum public for web app
///  3-14-26 Modify for Leaf update

import Foundation

public enum AuthTokenHeuristics {

    // Basic JWT pattern: header.payload.signature (base64url-ish)
    private static let jwtRegex: NSRegularExpression = {
        // Not perfect; good heuristic
        let pat = #"eyJ[a-zA-Z0-9_\-]+=*\.[a-zA-Z0-9_\-]+=*\.[a-zA-Z0-9_\-]+=*"#
        return (try? NSRegularExpression(pattern: pat, options: []))
            ?? (try! NSRegularExpression(pattern: "$^", options: []))
    }()

    private static let bearerRegex: NSRegularExpression = {
        let pat = #"(?i)\bBearer\s+([A-Za-z0-9\-\._~\+\/]+=*)\b"#
        return (try? NSRegularExpression(pattern: pat, options: []))
            ?? (try! NSRegularExpression(pattern: "$^", options: []))
    }()

    static func detectTokenLeaksInHeaders(_ headers: [String: String]) -> [Vulnerability] {
        var vulns: [Vulnerability] = []

        for (k, v) in headers {
            let key = k.lowercased()

            // Any response header containing Authorization/Bearer is suspicious
            if key == "authorization" || key.contains("auth") {
                if containsBearer(v) || containsJWT(v) {
                    vulns.append(
                        Vulnerability(
                            type: .exposedAuthToken,
                            description: "Response headers appear to include an auth token (\(k)).",
                            evidence: mask(v)
                        )
                    )
                }
            }

            // Set-Cookie checks
            if key == "set-cookie" {
                vulns.append(contentsOf: analyzeSetCookieHeader(v))
            }

            // Sometimes APIs echo token-ish data in custom headers
            if containsBearer(v) || containsJWT(v) {
                vulns.append(
                    Vulnerability(
                        type: .exposedAuthToken,
                        description: "Token-like value detected in response header: \(k)",
                        evidence: mask(v)
                    )
                )
            }
        }

        return vulns
    }

    static func detectTokenLeaksInBody(_ body: String) -> [Vulnerability] {
        var vulns: [Vulnerability] = []

        if containsJWT(body) {
            vulns.append(
                Vulnerability(
                    type: .exposedAuthToken,
                    description: "JWT-like token detected in response body.",
                    evidence: mask(firstJWT(in: body) ?? "jwt")
                )
            )
        }

        if containsBearer(body) {
            vulns.append(
                Vulnerability(
                    type: .exposedAuthToken,
                    description: "Bearer token detected in response body.",
                    evidence: mask(firstBearer(in: body) ?? "bearer")
                )
            )
        }

        return vulns
    }

    static func compareAuthVsUnauth(
        endpoint: Endpoint,
        unauth: (status: Int?, headers: [String: String], body: String?),
        auth: (status: Int?, headers: [String: String], body: String?)
    ) -> [Vulnerability] {

        // Heuristic: if unauth is 200 and auth is 200 and bodies are similar size, possible weak auth.
        // (Not definitive — just a finding to review.)
        let u = unauth.status ?? -1
        let a = auth.status ?? -1

        var vulns: [Vulnerability] = []

        let unauthLen = unauth.body?.utf8.count ?? 0
        let authLen = auth.body?.utf8.count ?? 0

        if u == 200 && a == 200 {
            let ratio = (max(unauthLen, authLen) == 0)
                ? 0.0
                : Double(min(unauthLen, authLen)) / Double(max(unauthLen, authLen))

            if ratio > 0.90 && unauthLen > 0 {
                vulns.append(
                    Vulnerability(
                        type: .authzBypass,
                        description: "Auth vs unauth look similar (possible weak auth). unauthLen=\(unauthLen), authLen=\(authLen), similarity≈\(String(format: "%.2f", ratio)).",
                        evidence: endpoint.url
                    )
                )
            }
        }

        // If unauth returns data with sensitive token patterns, flag harder
        if let ub = unauth.body, containsJWT(ub) || containsBearer(ub) {
            vulns.append(
                Vulnerability(
                    type: .authzBypass,
                    description: "Unauthenticated response contains token-like data.",
                    evidence: endpoint.url
                )
            )
        }

        // If unauth returns 200 but auth returns 401/403 (odd)
        if u == 200 && (a == 401 || a == 403) {
            vulns.append(
                Vulnerability(
                    type: .authzBypass,
                    description: "Unauthenticated request succeeded (HTTP 200) but authenticated request was denied (HTTP \(a)). Investigate auth routing/headers.",
                    evidence: endpoint.url
                )
            )
        }

        return vulns
    }

    // MARK: - Cookie analysis

    private static func analyzeSetCookieHeader(_ setCookie: String) -> [Vulnerability] {
        // Very lightweight parser: split cookies by comma is unsafe generally, but Set-Cookie is usually one per header.
        // Here we just inspect attributes.
        let lower = setCookie.lowercased()

        // Session-ish names
        let sessionNameLikely =
            lower.contains("session") ||
            lower.contains("sid=") ||
            lower.contains("jwt") ||
            lower.contains("token") ||
            lower.contains("auth")

        // Missing common security attrs
        let missingSecure = !lower.contains("secure")
        let missingHttpOnly = !lower.contains("httponly")
        let missingSameSite = !lower.contains("samesite")

        var vulns: [Vulnerability] = []

        if sessionNameLikely && (missingSecure || missingHttpOnly || missingSameSite) {
            var parts: [String] = []
            if missingSecure { parts.append("Secure") }
            if missingHttpOnly { parts.append("HttpOnly") }
            if missingSameSite { parts.append("SameSite") }

            vulns.append(
                Vulnerability(
                    type: .insecureCookie,
                    description: "Session-like cookie missing attributes: \(parts.joined(separator: ", ")).",
                    evidence: mask(setCookie)
                )
            )
        }

        return vulns
    }

    // MARK: - Helpers

    private static func containsJWT(_ text: String) -> Bool {
        let r = NSRange(text.startIndex..., in: text)
        return jwtRegex.firstMatch(in: text, range: r) != nil
    }

    private static func containsBearer(_ text: String) -> Bool {
        let r = NSRange(text.startIndex..., in: text)
        return bearerRegex.firstMatch(in: text, range: r) != nil
    }

    private static func firstJWT(in text: String) -> String? {
        let r = NSRange(text.startIndex..., in: text)
        guard let m = jwtRegex.firstMatch(in: text, range: r),
              let rr = Range(m.range, in: text) else { return nil }
        return String(text[rr])
    }

    private static func firstBearer(in text: String) -> String? {
        let r = NSRange(text.startIndex..., in: text)
        guard let m = bearerRegex.firstMatch(in: text, range: r),
              let rr = Range(m.range, in: text) else { return nil }
        return String(text[rr])
    }

    private static func mask(_ value: String) -> String {
        let t = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.count > 12 else { return "••••" }
        return "\(t.prefix(6))••••\(t.suffix(6))"
    }
}
