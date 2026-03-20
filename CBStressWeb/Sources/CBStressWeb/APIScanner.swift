//  APIScanner.swift
//  CBStressWeb
//
//  Created by Steven Petteruti on 2/17/26.
//  2-18-26 Modifed to repace extensions with @retroactive

import Foundation
import Vapor
import CBStressCore

/// Server-side scanner for Vapor.
/// Uses Vapor's `Client` (AsyncHTTPClient under the hood) to fetch responses,
/// then performs lightweight analysis (no Swift Concurrency required).
final class APIScanner {

    private let client: any Client

    init(client: any Client) {
        self.client = client
    }

    /// Scan a single endpoint (optionally applying AuthContext).
    func scan(endpoint: Endpoint, auth: AuthContext?) -> EventLoopFuture<ScanResult> {
        let authorizedEndpoint = endpoint.applying(auth: auth)

        guard let uri = URI(string: authorizedEndpoint.url).absoluteURI else {
            var bad = ScanResult(endpoint: authorizedEndpoint)
            bad.metadata["error"] = .string("Invalid URL: \(authorizedEndpoint.url)")
            return client.eventLoop.makeSucceededFuture(bad)
        }

        // Build Vapor headers
        var headers = HTTPHeaders()
        for (k, v) in authorizedEndpoint.headers {
            headers.replaceOrAdd(name: k, value: v)
        }

        // Build request
        var req = ClientRequest(method: HTTPMethod(rawValue: authorizedEndpoint.method.rawValue))
        req.url = uri
        req.headers = headers
        req.body = Self.makeBody(authorizedEndpoint.body)

        let start = DispatchTime.now()
        let loop = client.eventLoop

        return client.send(req).map { resp -> ScanResult in
            var result = ScanResult(endpoint: authorizedEndpoint)

            let elapsedNanos = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
            result.responseTime = Double(elapsedNanos) / 1_000_000_000.0
            result.statusCode = Int(resp.status.code)

            // Response headers
            var responseHeaders: [String: String] = [:]
            for (name, value) in resp.headers {
                responseHeaders[name] = value
            }
            result.responseHeaders = responseHeaders

            // Body string
            let bodyString: String = {
                guard var bb = resp.body else { return "" }
                return bb.readString(length: bb.readableBytes) ?? ""
            }()

            result.metadata["bodyString"] = .string(bodyString)

            // Analyze (static to avoid capturing self)
            result.vulnerabilities = Self.analyzeResponse(
                bodyString: bodyString,
                headers: responseHeaders,
                statusCode: Int(resp.status.code)
            )

            return result
        }
        .flatMapError { error in
            var failed = ScanResult(endpoint: authorizedEndpoint)
            failed.metadata["error"] = .string(error.localizedDescription)
            return loop.makeSucceededFuture(failed)
        }
    }

    // MARK: - Body

    private static func makeBody(_ body: String?) -> ByteBuffer? {
        guard let body, !body.isEmpty else { return nil }
        var buffer = ByteBufferAllocator().buffer(capacity: body.utf8.count)
        buffer.writeString(body)
        return buffer
    }

    // MARK: - Analysis (local, avoids CBStressCore internal APIs)

    private static func analyzeResponse(
        bodyString: String,
        headers: [String: String],
        statusCode: Int
    ) -> [Vulnerability] {

        var vulns: [Vulnerability] = []

        // 1) Basic API key / secret detection (lightweight)
        vulns.append(contentsOf: detectAPIKeys(in: bodyString))

        // 2) Token leaks
        vulns.append(contentsOf: detectTokenLeaksInHeaders(headers))
        vulns.append(contentsOf: detectTokenLeaksInBody(bodyString))

        // 3) Missing security headers
        vulns.append(contentsOf: checkSecurityHeaders(headers))

        // 4) Verbose errors
        if statusCode >= 500 {
            let lower = bodyString.lowercased()
            let looksVerbose =
                lower.contains("stack trace") ||
                lower.contains("exception") ||
                lower.contains("traceback") ||
                lower.contains("fatal error") ||
                lower.contains("undefined method") ||
                lower.contains("sqlstate")

            if looksVerbose {
                vulns.append(
                    Vulnerability(
                        type: .verboseError,
                        description: "Verbose server error returned",
                        evidence: String(bodyString.prefix(200))
                    )
                )
            }
        }

        return vulns
    }

    // MARK: - Detectors

    private static func detectAPIKeys(in text: String) -> [Vulnerability] {
        let patterns: [(VulnerabilityType, String, NSRegularExpression)] = [
            (.exposedAPIKey, "Potential API key exposed in response body",
             regex(#"\bsk-[A-Za-z0-9]{16,}\b"#)),

            (.exposedAPIKey, "Potential API key field exposed in response body",
             regex(#"(?i)\b(api[_-]?key|x-api-key)\b\s*[:=]\s*['""][^'""]{8,}['""]"#)),

            (.sensitiveData, "Potential secret exposed in response body",
             regex(#"(?i)\b(secret|client_secret|private_key)\b\s*[:=]\s*['""][^'""]{8,}['""]"#))
        ]

        var out: [Vulnerability] = []
        let ns = text as NSString

        for (type, desc, re) in patterns {
            if let match = re.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)) {
                let snippet = ns.substring(with: match.range)
                out.append(Vulnerability(type: type, description: desc, evidence: snippet))
            }
        }
        return out
    }

    private static func detectTokenLeaksInHeaders(_ headers: [String: String]) -> [Vulnerability] {
        var out: [Vulnerability] = []

        for (k, v) in headers {
            let key = k.lowercased()
            if key == "authorization" || key == "proxy-authorization" {
                out.append(
                    Vulnerability(
                        type: .exposedAuthToken,
                        description: "Authorization token appears in response headers",
                        evidence: "\(k): \(String(v.prefix(120)))"
                    )
                )
            }
        }

        if let setCookie = headers.first(where: { $0.key.lowercased() == "set-cookie" })?.value {
            let lower = setCookie.lowercased()
            let missingSecure = !lower.contains("secure")
            let missingHttpOnly = !lower.contains("httponly")
            let missingSameSite = !lower.contains("samesite")

            if missingSecure || missingHttpOnly || missingSameSite {
                var parts: [String] = []
                if missingSecure { parts.append("Secure") }
                if missingHttpOnly { parts.append("HttpOnly") }
                if missingSameSite { parts.append("SameSite") }

                out.append(
                    Vulnerability(
                        type: .insecureCookie,
                        description: "Session cookie missing attributes: \(parts.joined(separator: ", "))",
                        evidence: String(setCookie.prefix(200))
                    )
                )
            }
        }

        return out
    }

    private static func detectTokenLeaksInBody(_ text: String) -> [Vulnerability] {
        let jwt = regex(#"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"#)

        let ns = text as NSString
        if let m = jwt.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)) {
            let snippet = ns.substring(with: m.range)
            return [
                Vulnerability(
                    type: .exposedAuthToken,
                    description: "Possible JWT token exposed in response body",
                    evidence: snippet
                )
            ]
        }
        return []
    }

    private static func checkSecurityHeaders(_ headers: [String: String]) -> [Vulnerability] {
        let required = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]

        return required.compactMap { header in
            guard headers[header] == nil else { return nil }
            return Vulnerability(
                type: .missingSecurityHeader,
                description: "Missing security header: \(header)",
                evidence: nil
            )
        }
    }

    private static func regex(_ pattern: String) -> NSRegularExpression {
        try! NSRegularExpression(pattern: pattern, options: [])
    }
}

// URI helper for Vapor
private extension URI {
    var absoluteURI: URI? { self.string.isEmpty ? nil : self }
}

// MARK: - Swift 6 Sendable bridging for server-side use
extension AuthContext: @retroactive @unchecked Sendable {}
