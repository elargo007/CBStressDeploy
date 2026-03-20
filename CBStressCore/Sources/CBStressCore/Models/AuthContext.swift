///  AuthContext.swift
///  CBStress
///
///  Created by Steven Petteruti on 1/24/26 to hold authentication material (Bearer token / cookies) in a reusable, non-UI model.
///  2-17-26 Make struct public for web app

import Foundation

public struct AuthContext: Codable, Hashable {
    public var bearerToken: String?
    public var cookieHeader: String?

    public init(bearerToken: String? = nil, cookieHeader: String? = nil) {
        self.bearerToken = bearerToken
        self.cookieHeader = cookieHeader
    }
}
