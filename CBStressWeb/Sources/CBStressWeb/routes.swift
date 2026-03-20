/// Routes.swift
/// CBStressWeb
/// Created 2-17-26
/// 2-18-26 Modified for Web app
/// 3-14-26 Update for Leaf web app - update that keeps JSON/API routes and adds Leaf UI routes.

import Foundation
import Vapor
import Leaf
import CBStressCore
import CBStressReportKit

private func normalizedURL(_ raw: String) -> String {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://") {
        return trimmed
    }
    return "https://\(trimmed)"
}

private func htmlEscaped(_ text: String) -> String {
    text
        .replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
        .replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "'", with: "&#39;")
}

private func htmlReport(from report: ScanReport) -> String {
    let findingsHTML: String = {
        if report.result.vulnerabilities.isEmpty {
            return """
            <p class="muted">No findings detected.</p>
            """
        }

        return report.result.vulnerabilities.map { vuln in
            let evidenceHTML: String
            if let evidence = vuln.evidence, !evidence.isEmpty {
                evidenceHTML = """
                <div class="evidence"><strong>Evidence:</strong> \(htmlEscaped(evidence))</div>
                """
            } else {
                evidenceHTML = ""
            }

            return """
            <div class="finding-card">
                <div class="finding-top">
                    <div class="finding-title">\(htmlEscaped(vuln.description))</div>
                    <div class="badge">\(htmlEscaped(vuln.reportCategoryLabel))</div>
                </div>
                <div class="finding-meta">
                    <span class="chip">Risk \(vuln.reportRiskScore)</span>
                    <span class="chip">Exploitability \(vuln.reportExploitabilityScore)</span>
                    <span class="chip">Type \(htmlEscaped(String(describing: vuln.type)))</span>
                </div>
                \(evidenceHTML)
            </div>
            """
        }.joined(separator: "\n")
    }()

    let headersHTML: String = {
        if report.result.responseHeaders.isEmpty {
            return """
            <p class="muted">No response headers captured.</p>
            """
        }

        let rows = report.result.responseHeaders.keys.sorted().map { key in
            let value = report.result.responseHeaders[key] ?? ""
            return """
            <tr>
                <td class="header-key">\(htmlEscaped(key))</td>
                <td class="header-value">\(htmlEscaped(value))</td>
            </tr>
            """
        }.joined(separator: "\n")

        return """
        <table>
            <thead>
                <tr>
                    <th>Header</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                \(rows)
            </tbody>
        </table>
        """
    }()

    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>CBStress Results</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            :root {
                --bg: #f5f5f7;
                --card: #ffffff;
                --text: #111111;
                --muted: #6b7280;
                --line: #d1d5db;
                --soft: #f3f4f6;
            }

            * { box-sizing: border-box; }

            body {
                margin: 0;
                background: var(--bg);
                color: var(--text);
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.45;
            }

            .page {
                width: 100%;
                max-width: 900px;
                margin: 32px auto;
                padding: 0 20px 40px;
            }

            .sheet {
                background: var(--card);
                border: 1px solid var(--line);
                border-radius: 16px;
                padding: 28px;
                margin-bottom: 24px;
                box-shadow: 0 8px 24px rgba(0,0,0,0.06);
            }

            h1 {
                margin: 0 0 6px;
                font-size: 30px;
                font-weight: 700;
            }

            .subtitle {
                color: var(--muted);
                font-size: 13px;
                margin-bottom: 18px;
            }

            .divider {
                height: 1px;
                background: var(--line);
                margin: 14px 0 0;
            }

            h2 {
                margin: 0 0 14px;
                font-size: 18px;
                font-weight: 700;
            }

            .summary-card,
            .findings-card,
            .headers-card {
                border: 1px solid var(--line);
                border-radius: 14px;
                padding: 18px;
                background: #fff;
            }

            .summary-grid {
                display: grid;
                grid-template-columns: 150px 1fr;
                gap: 10px 14px;
                font-size: 14px;
            }

            .summary-label {
                font-weight: 600;
            }

            .summary-value {
                word-break: break-word;
            }

            .finding-card {
                border-top: 1px solid var(--line);
                padding: 14px 0;
            }

            .finding-card:first-child {
                border-top: 0;
                padding-top: 0;
            }

            .finding-top {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                gap: 12px;
                margin-bottom: 8px;
            }

            .finding-title {
                font-size: 15px;
                font-weight: 600;
            }

            .badge {
                white-space: nowrap;
                border: 1px solid rgba(0,0,0,0.35);
                border-radius: 999px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 700;
            }

            .finding-meta {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                margin-bottom: 8px;
            }

            .chip {
                background: var(--soft);
                border-radius: 999px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 600;
            }

            .evidence {
                color: var(--muted);
                font-size: 12px;
                word-break: break-word;
            }

            .muted {
                color: var(--muted);
                font-size: 14px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                font-size: 13px;
            }

            th, td {
                text-align: left;
                vertical-align: top;
                padding: 10px 8px;
                border-top: 1px solid var(--line);
            }

            thead th {
                border-top: 0;
                font-size: 12px;
                font-weight: 700;
            }

            .header-key {
                width: 220px;
                font-weight: 600;
                word-break: break-word;
            }

            .header-value {
                word-break: break-word;
            }

            @media print {
                body {
                    background: white;
                }

                .page {
                    max-width: none;
                    margin: 0;
                    padding: 0;
                }

                .sheet {
                    box-shadow: none;
                    border-radius: 0;
                    margin-bottom: 20px;
                    break-inside: avoid;
                }
            }
        </style>
    </head>
    <body>
        <main class="page">
            <section class="sheet">
                <h1>\(htmlEscaped(report.title))</h1>
                <div class="subtitle">\(htmlEscaped(ReportFormatting.timestamp(report.generatedAt)))</div>
                <div class="divider"></div>
            </section>

            <section class="sheet">
                <h2>Summary</h2>
                <div class="summary-card">
                    <div class="summary-grid">
                        <div class="summary-label">URL</div>
                        <div class="summary-value">\(htmlEscaped(report.result.endpoint.url))</div>

                        <div class="summary-label">Method</div>
                        <div class="summary-value">\(htmlEscaped(report.result.endpoint.method.rawValue))</div>

                        <div class="summary-label">Status Code</div>
                        <div class="summary-value">\(htmlEscaped(ReportFormatting.statusString(report.result.statusCode)))</div>

                        <div class="summary-label">Response Time</div>
                        <div class="summary-value">\(htmlEscaped(ReportFormatting.responseTimeString(report.result.responseTime)))</div>

                        <div class="summary-label">Findings</div>
                        <div class="summary-value">\(htmlEscaped(ReportFormatting.findingsCount(report.result)))</div>

                        <div class="summary-label">Response Headers</div>
                        <div class="summary-value">\(htmlEscaped(String(ReportFormatting.headerCount(report.result))))</div>
                    </div>
                </div>
            </section>

            <section class="sheet">
                <h2>Findings</h2>
                <div class="findings-card">
                    \(findingsHTML)
                </div>
            </section>

            <section class="sheet">
                <h2>Response Headers</h2>
                <div class="headers-card">
                    \(headersHTML)
                </div>
            </section>
        </main>
    </body>
    </html>
    """
}

func routes(_ app: Application) throws {

    struct ScanQuery: Content {
        var url: String
    }

    struct FindingRow: Content {
        let type: String
        let description: String
    }

    struct HeaderRow: Content {
        let key: String
        let value: String
    }

    struct ScanUIContext: Encodable {
        let url: String
        let statusCode: String
        let responseTime: String
        let findingCount: String
        let headerCount: String
        let hasFindings: Bool
        let hasHeaders: Bool
        let findings: [FindingRow]
        let headers: [HeaderRow]
    }

    app.get { req -> EventLoopFuture<View> in
        req.view.render("index")
    }

    app.get("hello") { _ in
        "Hello, world!"
    }

    app.get("core-check") { _ in
        "CBStressCore linked. Vulnerability types: \(VulnerabilityType.allCases.count)"
    }

    app.get("scan") { req -> EventLoopFuture<Response> in
        let q: ScanQuery
        do {
            q = try req.query.decode(ScanQuery.self)
        } catch {
            let r = Response(status: .badRequest)
            r.body = .init(string: #"{"error":"missing or invalid 'url' query param"}"#)
            return req.eventLoop.makeSucceededFuture(r)
        }

        let endpoint = Endpoint(url: normalizedURL(q.url), method: .GET)
        let scanner = APIScanner(client: req.client)

        return scanner.scan(endpoint: endpoint, auth: nil).flatMapThrowing { result in
            let res = Response(status: .ok)
            try res.content.encode(result, as: .json)
            return res
        }
    }

    app.get("report") { req -> EventLoopFuture<Response> in
        let q: ScanQuery
        do {
            q = try req.query.decode(ScanQuery.self)
        } catch {
            let r = Response(status: .badRequest)
            r.body = .init(string: #"{"error":"missing or invalid 'url' query param"}"#)
            return req.eventLoop.makeSucceededFuture(r)
        }

        let endpoint = Endpoint(url: normalizedURL(q.url), method: .GET)
        let scanner = APIScanner(client: req.client)

        return scanner.scan(endpoint: endpoint, auth: nil).flatMapThrowing { result in
            let report = ScanReport(result: result)
            let res = Response(status: .ok)
            try res.content.encode(report, as: .json)
            return res
        }
    }

    app.get("report.html") { req -> EventLoopFuture<Response> in
        let q: ScanQuery
        do {
            q = try req.query.decode(ScanQuery.self)
        } catch {
            let r = Response(status: .badRequest)
            r.body = .init(string: #"{"error":"missing or invalid 'url' query param"}"#)
            return req.eventLoop.makeSucceededFuture(r)
        }

        let endpoint = Endpoint(url: normalizedURL(q.url), method: .GET)
        let scanner = APIScanner(client: req.client)

        return scanner.scan(endpoint: endpoint, auth: nil).flatMapThrowing { result in
            let report = ScanReport(result: result)
            let html = htmlReport(from: report)

            var headers = HTTPHeaders()
            headers.add(name: .contentType, value: "text/html; charset=utf-8")
            headers.add(name: .contentDisposition, value: #"attachment; filename="CBStress Results.html""#)

            return Response(
                status: .ok,
                headers: headers,
                body: .init(string: html)
            )
        }
    }

    app.get("scan-ui") { req -> EventLoopFuture<View> in
        let q: ScanQuery
        do {
            q = try req.query.decode(ScanQuery.self)
        } catch {
            return req.view.render("index")
        }

        let endpoint = Endpoint(url: normalizedURL(q.url), method: .GET)
        let scanner = APIScanner(client: req.client)

        return scanner.scan(endpoint: endpoint, auth: nil).flatMap { result in
            let findings = result.vulnerabilities.map {
                FindingRow(type: "\($0.type)", description: $0.description)
            }

            let headers = result.responseHeaders
                .keys
                .sorted()
                .map { HeaderRow(key: $0, value: result.responseHeaders[$0] ?? "") }

            let context = ScanUIContext(
                url: endpoint.url,
                statusCode: result.statusCode.map(String.init) ?? "—",
                responseTime: result.responseTime.map { String(format: "%.3f sec", $0) } ?? "—",
                findingCount: String(result.vulnerabilities.count),
                headerCount: String(result.responseHeaders.count),
                hasFindings: !findings.isEmpty,
                hasHeaders: !headers.isEmpty,
                findings: findings,
                headers: headers
            )

            return req.view.render("result", context)
        }
    }
}
