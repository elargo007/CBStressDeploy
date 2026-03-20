///  ResultsPDFHeadersPageView.swift
///  CBStressReportKit
///
///  Created by Steven Petteruti on 3/14/26.

import Foundation
import CBStressCore

#if canImport(SwiftUI)
import SwiftUI

@available(iOS 16.0, macOS 13.0, *)
public struct ResultsPDFHeadersPageView: View {
    public let report: ScanReport
    public let pageSize: CGSize
    public let margin: CGFloat

    public init(report: ScanReport, pageSize: CGSize, margin: CGFloat) {
        self.report = report
        self.pageSize = pageSize
        self.margin = margin
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Response Headers")
                    .font(.system(size: 22, weight: .bold))

                Text("Page 2")
                    .font(.system(size: 11))
                    .foregroundColor(.gray)

                Divider()
            }

            if report.result.responseHeaders.isEmpty {
                Text("No response headers captured.")
                    .font(.system(size: 12))
                    .foregroundColor(.gray)
            } else {
                VStack(spacing: 0) {
                    HStack {
                        Text("Header")
                            .font(.system(size: 11, weight: .bold))
                            .frame(width: 180, alignment: .leading)

                        Text("Value")
                            .font(.system(size: 11, weight: .bold))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.vertical, 8)

                    Divider()

                    ForEach(report.result.responseHeaders.keys.sorted(), id: \.self) { key in
                        HStack(alignment: .top, spacing: 10) {
                            Text(key)
                                .font(.system(size: 10, weight: .semibold))
                                .frame(width: 180, alignment: .leading)

                            Text(report.result.responseHeaders[key] ?? "")
                                .font(.system(size: 10))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .padding(.vertical, 6)

                        Divider()
                    }
                }
            }

            Spacer(minLength: 0)
        }
        .frame(width: pageSize.width, height: pageSize.height, alignment: .topLeading)
        .padding(margin)
        .background(Color.white)
        .foregroundColor(.black)
    }
}

#else

public struct ResultsPDFHeadersPageView {
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
