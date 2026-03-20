///  AppVersion.swift
///  CBStress
///
///  Created by Steven Petteruti on 1/28/26 as helper file used for modularity in ContentView, ResultsView, and ResultsPDFPage1View.
///  2-17-26 Make enum public for web app

import Foundation

public enum AppVersion {

    /// Returns "Version.Build" from Info.plist (CFBundleShortVersionString + CFBundleVersion)
    static var versionBuild: String {
        let v = (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let b = (Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let version = (v?.isEmpty == false) ? v! : "—"
        let build = (b?.isEmpty == false) ? b! : "—"
        return "\(version).\(build)"
    }
}
