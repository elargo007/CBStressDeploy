///  PDFRenderer.swift
///  CBStressReportKit
///
///  Created by Steven Petteruti on 3/14/26.

import Foundation

#if canImport(SwiftUI) && canImport(CoreGraphics)

import SwiftUI
import CoreGraphics

@available(iOS 16.0, macOS 13.0, *)
public enum PDFRenderer {

    @MainActor
    public static func makePDF(report: ScanReport) -> Data {

        let pageSize = CGSize(width: 612, height: 792) // US Letter
        let margin: CGFloat = 24

        let data = NSMutableData()
        var mediaBox = CGRect(origin: .zero, size: pageSize)

        guard let consumer = CGDataConsumer(data: data as CFMutableData),
              let context = CGContext(consumer: consumer, mediaBox: &mediaBox, nil)
        else {
            return Data()
        }

        let page1 = ImageRenderer(
            content: ResultsPDFPage1View(
                report: report,
                pageSize: pageSize,
                margin: margin
            )
        )
        page1.scale = 2.0

        context.beginPDFPage(nil)
        if let image = page1.cgImage {
            context.draw(image, in: mediaBox)
        }
        context.endPDFPage()

        let page2 = ImageRenderer(
            content: ResultsPDFHeadersPageView(
                report: report,
                pageSize: pageSize,
                margin: margin
            )
        )
        page2.scale = 2.0

        context.beginPDFPage(nil)
        if let image = page2.cgImage {
            context.draw(image, in: mediaBox)
        }
        context.endPDFPage()

        context.closePDF()
        return data as Data
    }
}

#else

// Linux / Docker fallback so server builds succeed

public enum PDFRenderer {

    public static func makePDF(report: ScanReport) -> Data {
        print("PDFRenderer: PDF generation not supported on this platform.")
        return Data()
    }
}

#endif
