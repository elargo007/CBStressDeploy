///  ResultsPDFPage1View.swift
///  CBStressReportKit
///
///  Created by Steven Petteruti on 3/14/26.

import Foundation
import CBStressCore

#if canImport(SwiftUI)
import SwiftUI

@available(iOS 16.0, macOS 13.0, *)
public struct ResultsPDFPage1View: View {
    public let report: ScanReport
    public let pageSize: CGSize
    public let margin: CGFloat

    public init(report: ScanReport, pageSize: CGSize, margin: CGFloat) {
        self.report = report
        self.pageSize = pageSize
        self.margin = margin
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            summaryCard
            findingsCard
            Spacer(minLength: 0)
        }
        .frame(width: pageSize.width, height: pageSize.height, alignment: .topLeading)
        .padding(margin)
        .background(Color.white)
        .foregroundColor(.black)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(report.title)
                .font(.system(size: 22, weight: .bold))

            Text(ReportFormatting.timestamp(report.generatedAt))
                .font(.system(size: 11))
                .foregroundColor(.gray)

            Divider()
        }
    }

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Summary")
                .font(.system(size: 15, weight: .bold))

            summaryRow("URL", report.result.endpoint.url)
            summaryRow("Method", report.result.endpoint.method.rawValue)
            summaryRow("Status Code", ReportFormatting.statusString(report.result.statusCode))
            summaryRow("Response Time", ReportFormatting.responseTimeString(report.result.responseTime))
            summaryRow("Findings", ReportFormatting.findingsCount(report.result))
            summaryRow("Response Headers", "\(ReportFormatting.headerCount(report.result)) (see page 2)")
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color.gray.opacity(0.35), lineWidth: 1)
        )
    }

    private var findingsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Findings")
                .font(.system(size: 15, weight: .bold))

            if report.result.vulnerabilities.isEmpty {
                Text("No findings detected.")
                    .font(.system(size: 12))
                    .foregroundColor(.gray)
            } else {
                ForEach(Array(report.result.vulnerabilities.enumerated()), id: \.element.id) { _, vuln in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(alignment: .top) {
                            Text(vuln.description)
                                .font(.system(size: 12, weight: .semibold))
                            Spacer()
                            badge(vuln.reportCategoryLabel)
                        }

                        if let evidence = vuln.evidence, !evidence.isEmpty {
                            Text(evidence)
                                .font(.system(size: 10))
                                .foregroundColor(.gray)
                                .lineLimit(3)
                        }

                        HStack(spacing: 8) {
                            chip("Risk \(vuln.reportRiskScore)")
                            chip("Exploitability \(vuln.reportExploitabilityScore)")
                        }
                    }
                    .padding(.vertical, 8)

                    Divider()
                }
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color.gray.opacity(0.35), lineWidth: 1)
        )
    }

    private func summaryRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text(label)
                .font(.system(size: 11, weight: .semibold))
                .frame(width: 110, alignment: .leading)

            Text(value.isEmpty ? "—" : value)
                .font(.system(size: 11))
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func badge(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .bold))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .overlay(
                Capsule().stroke(Color.black.opacity(0.5), lineWidth: 1)
            )
    }

    private func chip(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .medium))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
                Capsule().fill(Color.black.opacity(0.06))
            )
    }
}

#else

public struct ResultsPDFPage1View {
    public let report: ScanReport
    public let pageSize: CGSize
    public let margin: CGFloat

    public init(report: ScanReport, pageSize: CGSize, margin: CGFloat) {
        self.report = report
        self.pageSize = pageSize
        self.margin = margin
    }
}

#endif
